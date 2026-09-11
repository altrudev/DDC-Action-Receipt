from datetime import datetime, timezone
from ddcar.crypto import generate_keypair, sha256_digest, sha256_bytes
from ddcar.model import *

T='2026-09-06T12:00:00Z'; E='2026-09-06T13:00:00Z'
NOW=datetime(2026,9,6,12,30,tzinfo=timezone.utc)

def physical_fixture(scope=None, params=None):
    keys={role:generate_keypair() for role in ('authority','decision','execution')}
    trust={role:{role+'-key':pair[1]} for role,pair in keys.items()}
    trust['bindings']={'authority':{'authority-key':'human:h'},'decision':{'decision-key':'gate:g'},'execution':{'execution-key':'exec:e'}}
    scope=scope or {'tool_id':'sim:arm-01','operation':'move','frame':'sim-base',
        'workspace':{'x':['-500','500'],'y':['-500','500'],'z':['0','500']},
        'max_speed':'100','max_force':'20'}
    params=params or {'target':{
        'x':{'value':'10','unit':'mm','frame':'sim-base'},
        'y':{'value':'20','unit':'mm','frame':'sim-base'},
        'z':{'value':'100','unit':'mm','frame':'sim-base'}},
        'speed':{'value':'20','unit':'mm/s'},'force':{'value':'5','unit':'N'}}
    tool={'kind':'physical-gate','id':'sim:arm-01','version':'0.2','schema_digest':sha256_digest('arm-v02')}
    action=action_core(tool,'move',params)
    grant=authority_grant('human:h',scope,E,'a'*32,issued_at=T,agent='agent:a',action_digest=sha256_digest(action))
    ap=sign_authority(grant,keys['authority'][0],'authority-key')
    r=make_receipt(receipt_id='physical-r1',nonce='b'*32,agent={'id':'agent:a'},
      authority={'kind':'human','principal':'human:h','basis':'explicit-physical-approval','scope':scope},
      authority_grant=grant,authority_proof=ap,tool=tool,operation='move',parameters=params,
      evidence=[{'type':'physical-state','digest':sha256_bytes(b'state'),'observed_at':T,'valid_until':E}],
      policy={'id':'physical','version':'0.2','digest':sha256_digest('p')},
      prerequisites=[{'status':'PASS'}],permissions=[{'status':'PASS'}],
      assurance={d:{'status':'PASS'} for d in REQUIRED_DIMENSIONS},anomalies=[],risk={'class':'medium'},
      decision='ALLOW',issuer={'id':'gate:g'},expires_at=E,issued_at=T)
    r=seal_decision(r,keys['decision'][0],'decision-key')
    r=bind_execution(r,tool=tool,operation='move',parameters=params,
      outcome={'status':'SUCCEEDED','evidence_digest':sha256_digest('simulated')},
      executor={'id':'exec:e'},private_key=keys['execution'][0],key_id='execution-key',
      observed_at='2026-09-06T12:05:00Z')
    return r,keys,trust

def verify(r,t,**kw): return verify_receipt(r,trust=t,now=NOW,**kw)

def test_physical_scope_valid():
    r,k,t=physical_fixture()
    assert verify(r,t)==[]

def test_physical_workspace_exceeded_fails_closed():
    r,k,t=physical_fixture()
    r['requested_action']['parameters']['target']['x']['value']='501'
    r['requested_action_digest']=sha256_digest(r['requested_action'])
    r['execution']=None; r['execution_proof']=None; r['decision_proof']=None
    r=seal_decision(r,k['decision'][0],'decision-key')
    assert any('scope' in e for e in verify(r,t,require_execution=False))

def test_physical_frame_mismatch_fails_closed():
    r,k,t=physical_fixture()
    r['requested_action']['parameters']['target']['x']['frame']='world'
    r['requested_action_digest']=sha256_digest(r['requested_action'])
    r['execution']=None; r['execution_proof']=None; r['decision_proof']=None
    r=seal_decision(r,k['decision'][0],'decision-key')
    assert any('scope' in e for e in verify(r,t,require_execution=False))

def test_physical_speed_force_limits():
    for field,value in [('speed','101'),('force','21')]:
        r,k,t=physical_fixture()
        r['requested_action']['parameters'][field]['value']=value
        r['requested_action_digest']=sha256_digest(r['requested_action'])
        r['execution']=None; r['execution_proof']=None; r['decision_proof']=None
        r=seal_decision(r,k['decision'][0],'decision-key')
        assert any('scope' in e for e in verify(r,t,require_execution=False))

def test_unknown_physical_constraint_still_fails_closed():
    scope={'tool_id':'sim:arm-01','operation':'move','max_energy':'10'}
    r,k,t=physical_fixture(scope=scope)
    assert any('scope' in e for e in verify(r,t))

def test_physical_scope_delegation_cannot_expand():
    parent,k,t=physical_fixture()
    child=__import__('copy').deepcopy(parent)
    child['receipt_id']='child'
    child['nonce']='c'*32
    child['lineage']['previous']=[receipt_digest(parent)]
    child['lineage']['delegation_parent']=receipt_digest(parent)
    child['authority_grant']['delegation_parent']=receipt_digest(parent)
    child['agent']={'id':'agent:b'}
    child['authority_grant']['agent']='agent:b'
    child['authority']['scope']['max_speed']='200'
    child['authority_grant']['scope']['max_speed']='200'
    child['authority_proof']=sign_authority(child['authority_grant'],k['authority'][0],'authority-key')
    child['decision_proof']=None; child['execution']=None; child['execution_proof']=None
    child=seal_decision(child,k['decision'][0],'decision-key')
    errs=verify(child,t,previous_receipts={receipt_digest(parent):parent},require_execution=False)
    assert any('delegation expands' in e or 'scope' in e for e in errs)
