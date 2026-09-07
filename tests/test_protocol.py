import json, os, subprocess, sys, threading
from copy import deepcopy
from datetime import datetime, timezone
import pytest
from ddcar.crypto import generate_keypair, sha256_digest, sha256_bytes, sign_obj
from ddcar.model import *
from ddcar.replay import ReplayStore
from ddcar.adapters import execute_committed, mcp_action, http_action, github_action

T='2026-09-06T12:00:00Z'; E='2026-09-06T13:00:00Z'
NOW=datetime(2026,9,6,12,30,tzinfo=timezone.utc)

def fixture(decision='ALLOW',scope=None):
    keys={role:generate_keypair() for role in ('authority','decision','execution')}
    trust={role:{role+'-key':pair[1]} for role,pair in keys.items()}
    trust['bindings']={'authority':{'authority-key':'human:h'},'decision':{'decision-key':'gate:g'},'execution':{'execution-key':'exec:e'}}
    scope=scope or {'max_amount':'25.00','currency':'CAD','destination':'A','tool_id':'bank','operation':'transfer'}
    tool={'kind':'api','id':'bank','version':'1','schema_digest':sha256_digest('bank-v1')}
    grant=authority_grant('human:h',scope,E,'a'*32,issued_at=T,agent='agent:a',action_digest=sha256_digest(action_core(tool,'transfer',{'amount':'10.00','to':'A','currency':'CAD'})))
    ap=sign_authority(grant,keys['authority'][0],'authority-key')
    r=make_receipt(receipt_id='r1',nonce='b'*32,agent={'id':'agent:a'},authority={'kind':'human','principal':'human:h','basis':'explicit-approval','scope':scope},authority_grant=grant,authority_proof=ap,tool=tool,operation='transfer',parameters={'amount':'10.00','to':'A','currency':'CAD'},evidence=[{'type':'state','digest':sha256_bytes(b'state'),'observed_at':T,'valid_until':E}],policy={'id':'p','version':'1','digest':sha256_digest('p1')},prerequisites=[{'status':'PASS'}],permissions=[{'status':'PASS'}],assurance={d:{'status':'PASS'} for d in REQUIRED_DIMENSIONS},anomalies=[],risk={'class':'low'},decision=decision,issuer={'id':'gate:g'},expires_at=E,issued_at=T)
    r=seal_decision(r,keys['decision'][0],'decision-key')
    if decision=='ALLOW': r=bind_execution(r,tool=tool,operation='transfer',parameters={'amount':'10.00','to':'A','currency':'CAD'},outcome={'status':'SUCCEEDED','evidence_digest':sha256_digest('bank-result')},executor={'id':'exec:e'},private_key=keys['execution'][0],key_id='execution-key',observed_at='2026-09-06T12:05:00Z')
    return r,keys,trust

def verify(r,trust,**kw): return verify_receipt(r,trust=trust,now=NOW,**kw)
def test_valid():
    r,k,t=fixture(); assert verify(r,t)==[]
def test_tampering():
    r,k,t=fixture(); r['risk']['class']='high'; assert verify(r,t)
def test_substitution():
    r,k,t=fixture(); r['execution']['exact_action']['parameters']['to']='B'; assert any('substitution' in e for e in verify(r,t))
def test_distinct_keys():
    r,k,t=fixture(); t['execution']['execution-key']=t['decision']['decision-key']; assert verify(r,t)
def test_forged_decision():
    r,k,t=fixture(); r['decision_proof']['signature']=sign_obj(payload(r),k['execution'][0],'decision-v0.1'); assert verify(r,t)
def test_forged_authority():
    r,k,t=fixture(); r['authority_grant']['scope']['max_amount']='999'; assert verify(r,t)
def test_scope():
    r,k,t=fixture(); r['authority']['scope']['max_amount']='999'; r=seal_again(r,k); assert any('scope' in e for e in verify(r,t))
def seal_again(r,k):
    r['decision_proof']=None; r['execution']=None; r['execution_proof']=None
    return seal_decision(r,k['decision'][0],'decision-key')
def test_replay(tmp_path):
    db=ReplayStore(tmp_path/'r.db'); assert db.reserve('gate','n','d'); assert not db.reserve('gate','n','d'); db.close()
    db=ReplayStore(tmp_path/'r.db'); assert not db.reserve('gate','n','d'); assert db.reserve('other','n','d'); db.close()
def test_stale_evidence():
    r,k,t=fixture(); r['evidence'][0]['valid_until']='2026-09-06T12:01:00Z'; assert verify(r,t)
def test_historical_expiry():
    r,k,t=fixture(); assert verify_receipt(r,trust=t,now=datetime(2030,1,1,tzinfo=timezone.utc))==[]
    assert verify_receipt(r,trust=t,now=datetime(2030,1,1,tzinfo=timezone.utc),mode='preflight')
def test_future_or_backdated_execution():
    r,k,t=fixture(); r['execution']['observed_at']='2026-09-06T11:00:00Z'; assert verify(r,t)
def test_missing_parent():
    r,k,t=fixture(); r['lineage']['previous']=[sha256_digest('fake')]; assert verify(r,t,previous_receipts={})
def test_forged_parent():
    r,k,t=fixture(); r['lineage']['previous']=[sha256_digest('fake')]; assert any('forged' in e for e in verify(r,t,previous_receipts={sha256_digest('fake'):r}))
def test_delegation_expansion():
    parent,k,t=fixture(); child=deepcopy(parent); child['receipt_id']='child'; child['nonce']='c'*32; child['authority']['scope']['max_amount']='100'; child['lineage']['previous']=[receipt_digest(parent)]; child['lineage']['delegation_parent']=receipt_digest(parent); child['authority_grant']['delegation_parent']=receipt_digest(parent); child['agent']={'id':'agent:b'}; child['authority_grant']['agent']='agent:b'; child['authority_grant']['scope']['max_amount']='100'; child['authority_proof']=sign_authority(child['authority_grant'],k['authority'][0],'authority-key'); child=seal_again(child,k); assert any('delegation expands' in e for e in verify(child,t,previous_receipts={receipt_digest(parent):parent},require_execution=False))
def test_block_review():
    for d in ('BLOCK','HUMAN-REVIEW'):
        r,k,t=fixture(d); assert verify(r,t)==[]
def test_allow_failed_constraint():
    r,k,t=fixture(); r['permissions']=[{'status':'FAIL'}]; r=seal_again(r,k)
    assert any('failed constraints' in e for e in verify(r,t,require_execution=False))

def test_canonical_rejection():
    from ddcar.canonical import loads, canonical_bytes
    for data in ('{"a":1,"a":2}','{"x":1.0}','{"x":NaN}'):
        with pytest.raises(ValueError): loads(data)
    with pytest.raises(ValueError): canonical_bytes({'x':2**60})
    with pytest.raises(ValueError): canonical_bytes({'x':'\ud800'})
def test_schema_unknown_field():
    r,k,t=fixture(); r['surprise']=1; assert verify(r,t)
def test_external_evidence():
    r,k,t=fixture(); assert verify(r,t,external_evidence={sha256_bytes(b'state'):b'state'})==[]
    assert verify(r,t,external_evidence={sha256_bytes(b'state'):b'wrong'})
def test_adapter_shapes():
    assert mcp_action('s','t',{},b'{}')['tool']['schema_digest']==sha256_bytes(b'{}')
    with pytest.raises(ValueError): http_action('POST','http://unsafe',b'{}')
    with pytest.raises(ValueError): github_action('o/r','commit',{},'')
def test_executor(tmp_path):
    r,k,t=fixture(); r=seal_again(r,k)
    calls=[]; db=ReplayStore(tmp_path/'exec.db')
    def transport(action):
        calls.append(action); return {'status':'SUCCEEDED','evidence_digest':sha256_digest('ok'),'sent_action_digest':sha256_digest(action)}
    result=execute_committed(r,trust=t,transport=transport,executor={'id':'exec:e'},private_key=k['execution'][0],key_id='execution-key',replay_store=db,now=NOW)
    assert len(calls)==1 and verify(result,t)==[]
    with pytest.raises(ValueError,match='replay'): execute_committed(r,trust=t,transport=transport,executor={'id':'exec:e'},private_key=k['execution'][0],key_id='execution-key',replay_store=db,now=NOW)
    assert len(calls)==1; db.close()
def test_cli(tmp_path):
    r,k,t=fixture(); (tmp_path/'r.json').write_text(json.dumps(r)); (tmp_path/'trust.json').write_text(json.dumps(t))
    cmd=[sys.executable,'-m','ddcar.cli','verify',str(tmp_path/'r.json'),'--trust',str(tmp_path/'trust.json'),'--replay-db',str(tmp_path/'r.db')]
    a=subprocess.run(cmd,capture_output=True,text=True); assert a.returncode==0,a.stdout
    b=subprocess.run(cmd,capture_output=True,text=True); assert b.returncode==2 and 'replay' in b.stdout

def test_grant_binds_exact_action_and_agent():
    r,k,t=fixture(); r['agent']['id']='agent:other'; r=seal_again(r,k)
    assert any('action/agent' in e for e in verify(r,t,require_execution=False))
    r,k,t=fixture(); r['requested_action']['parameters']['amount']='11.00'; r['requested_action_digest']=sha256_digest(r['requested_action']); r=seal_again(r,k)
    assert any('action/agent' in e for e in verify(r,t,require_execution=False))

def test_identity_binding():
    r,k,t=fixture(); t['bindings']['decision']['decision-key']='other'; assert verify(r,t)
    r,k,t=fixture(); t['bindings']['authority']['authority-key']='other'; assert verify(r,t)
    r,k,t=fixture(); t['bindings']['execution']['execution-key']='other'; assert verify(r,t)

def test_unknown_scope_fails_closed():
    r,k,t=fixture(); r['authority']['scope']['unrecognized_permission']='all'; r=seal_again(r,k)
    assert any('scope' in e for e in verify(r,t,require_execution=False))

def test_decimal_limits():
    r,k,t=fixture(); r['requested_action']['parameters']['amount']='1000'; r['requested_action_digest']=sha256_digest(r['requested_action']); r=seal_again(r,k)
    assert any('scope' in e for e in verify(r,t,require_execution=False))
    r,k,t=fixture(); r['requested_action']['parameters']['amount']='NaN'; r['requested_action_digest']=sha256_digest(r['requested_action']); r=seal_again(r,k)
    assert any('scope' in e for e in verify(r,t,require_execution=False))

def test_unresolved_constraints_fail_closed():
    for status in ('WARN','UNRESOLVED','FAIL'):
        r,k,t=fixture(); r['assurance']['security']['status']=status; r=seal_again(r,k)
        assert verify(r,t,require_execution=False)
    r,k,t=fixture(); r['assurance'].pop('authority'); r=seal_again(r,k)
    assert verify(r,t,require_execution=False)

def test_frequency_cannot_override_authority():
    r,k,t=fixture(); r['assurance']['frequency']={'status':'WARN'}; r=seal_again(r,k)
    assert verify(r,t,require_execution=False)==[]
    r['assurance']['authority']['status']='FAIL'; r=seal_again(r,k)
    assert verify(r,t,require_execution=False)

def test_missing_lineage_bundle_fails_closed():
    r,k,t=fixture(); r['lineage']['previous']=[sha256_digest('missing')]; r=seal_again(r,k)
    assert any('lineage parents not supplied' in e for e in verify(r,t,require_execution=False))

def test_related_parent_does_not_require_inherited_scope():
    p,k,t=fixture(); r=deepcopy(p); r['receipt_id']='related'; r['nonce']='d'*32
    r['lineage']['previous']=[receipt_digest(p)]; r=seal_again(r,k)
    assert verify(r,t,previous_receipts={receipt_digest(p):p},require_execution=False)==[]

def test_delegation_parent_must_be_present():
    r,k,t=fixture(); r['lineage']['delegation_parent']=sha256_digest('missing'); r=seal_again(r,k)
    assert any('delegation' in e for e in verify(r,t,require_execution=False))

def test_aliasing_regression():
    r,k,t=fixture(); before=deepcopy(r['authority_grant'])
    r['authority']['scope']['max_amount']='999'
    assert r['authority_grant']==before

def test_canonical_utf16_order_and_limits():
    from ddcar.canonical import canonical_bytes, loads, MAX_BYTES
    assert canonical_bytes({'\ue000':1,'\U00010000':2})==b'{"\xf0\x90\x80\x80":2,"\xee\x80\x80":1}'
    with pytest.raises(ValueError): loads(b' '*MAX_BYTES+b'{}')

def test_executor_rejects_untrusted_key_before_transport(tmp_path):
    r,k,t=fixture(); r=seal_again(r,k); db=ReplayStore(tmp_path/'r.db'); calls=[]
    bad,_=generate_keypair()
    with pytest.raises(ValueError,match='executor key'):
        execute_committed(r,trust=t,transport=lambda a:calls.append(a),executor={'id':'exec:e'},private_key=bad,key_id='execution-key',replay_store=db,now=NOW)
    assert calls==[]; db.close()

def test_executor_rejects_transport_substitution(tmp_path):
    r,k,t=fixture(); r=seal_again(r,k); db=ReplayStore(tmp_path/'r.db')
    def bad(a): return {'status':'SUCCEEDED','evidence_digest':sha256_digest('x'),'sent_action_digest':sha256_digest('wrong')}
    with pytest.raises(ValueError,match='exact-action attestation'):
        execute_committed(r,trust=t,transport=bad,executor={'id':'exec:e'},private_key=k['execution'][0],key_id='execution-key',replay_store=db,now=NOW)
    assert not db.reserve('gate:g',r['nonce'],sha256_digest(r)); db.close()

def test_replay_concurrent(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    path=tmp_path/'concurrent.db'
    def reserve(_):
        db=ReplayStore(path)
        try: return db.reserve('domain','nonce','digest')
        finally: db.close()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(reserve,range(16)))
    assert results.count(True)==1

def test_executor_requires_actual_request_attestation(tmp_path):
    r,k,t=fixture(); r=seal_again(r,k); db=ReplayStore(tmp_path/'r.db')
    def unproven(a): return {'status':'SUCCEEDED','evidence_digest':sha256_digest('claimed')}
    with pytest.raises(ValueError,match='exact-action attestation'):
        execute_committed(r,trust=t,transport=unproven,executor={'id':'exec:e'},private_key=k['execution'][0],key_id='execution-key',replay_store=db,now=NOW)
    db.close()

def test_empty_evidence_and_checks_fail_closed():
    for field in ('evidence','permissions','prerequisites'):
        r,k,t=fixture(); r[field]=[]; r=seal_again(r,k)
        assert verify(r,t,require_execution=False)
