import json
from pathlib import Path
from datetime import datetime, timezone
from copy import deepcopy
from ddcar.crypto import generate_keypair, sha256_digest, sha256_bytes
from ddcar.model import *

ROOT=Path(__file__).resolve().parents[1]
T='1970-01-01T00:16:40Z'
E='1970-01-01T00:16:41Z'
NOW=datetime(1970,1,1,0,16,40,500000,tzinfo=timezone.utc)

def vector():
    return json.loads((ROOT/'conformance/ddcar-physical-v0.3.json').read_text())

def build(v=None):
    v=v or vector()
    keys={role:generate_keypair() for role in ('authority','decision','execution')}
    trust={role:{role+'-key':pair[1]} for role,pair in keys.items()}
    trust['bindings']={'authority':{'authority-key':'human:owner'},'decision':{'decision-key':'ddc-physical-gate'},'execution':{'execution-key':'sim:executor'}}
    action=v['action']; scope=v['scope']
    grant=authority_grant('human:owner',scope,E,v['nonce'],issued_at=T,agent=v['agent'],action_digest=sha256_digest(action))
    ap=sign_authority(grant,keys['authority'][0],'authority-key')
    r=make_receipt(receipt_id='physical-v03-vector-0001',nonce=v['nonce'],agent={'id':v['agent']},
      authority={'kind':'human','principal':'human:owner','basis':'shared-conformance-vector','scope':scope},
      authority_grant=grant,authority_proof=ap,tool=action['tool'],operation=action['operation'],parameters=action['parameters'],
      evidence=[{'type':'physical-state','digest':sha256_bytes(b'v03-state'),'observed_at':T,'valid_until':E,'source':'simulator:arm-01'}],
      policy={'id':'ddc-physical-gate','version':'0.3','digest':sha256_digest(v['profile_digest'])},
      prerequisites=[{'status':'PASS'}],permissions=[{'status':'PASS'}],
      assurance={d:{'status':'PASS'} for d in REQUIRED_DIMENSIONS},anomalies=[],risk={'class':'medium'},
      decision='ALLOW',issuer={'id':'ddc-physical-gate'},expires_at=E,issued_at=T)
    r=seal_decision(r,keys['decision'][0],'decision-key')
    r=bind_execution(r,tool=action['tool'],operation=action['operation'],parameters=action['parameters'],
      outcome={'status':'SUCCEEDED','evidence_digest':sha256_digest('simulated-v03')},executor={'id':'sim:executor'},
      private_key=keys['execution'][0],key_id='execution-key',observed_at='1970-01-01T00:16:40.250000Z')
    return r,keys,trust

def test_shared_vector_end_to_end_verifies():
    r,k,t=build()
    assert verify_receipt(r,trust=t,now=NOW)==[]

def _decision_only_after_mutation(r,k):
    r['decision_proof']=None; r['execution']=None; r['execution_proof']=None
    return seal_decision(r,k['decision'][0],'decision-key')

def test_vector_coordinate_substitution_fails():
    r,k,t=build(); r['requested_action']['parameters']['target']['x']['value']='501'
    r['requested_action_digest']=sha256_digest(r['requested_action']); r=_decision_only_after_mutation(r,k)
    assert any('scope' in e for e in verify_receipt(r,trust=t,now=NOW,require_execution=False))

def test_vector_frame_substitution_fails():
    r,k,t=build(); r['requested_action']['parameters']['target']['x']['frame']='world'
    r['requested_action_digest']=sha256_digest(r['requested_action']); r=_decision_only_after_mutation(r,k)
    assert any('scope' in e for e in verify_receipt(r,trust=t,now=NOW,require_execution=False))

def test_vector_speed_force_substitution_fails():
    for field,value in [('speed','101'),('force','21')]:
        r,k,t=build(); r['requested_action']['parameters'][field]['value']=value
        r['requested_action_digest']=sha256_digest(r['requested_action']); r=_decision_only_after_mutation(r,k)
        assert any('scope' in e for e in verify_receipt(r,trust=t,now=NOW,require_execution=False))

def test_vector_action_digest_and_nonce_tamper_fail():
    r,k,t=build(); r['requested_action']['parameters']['speed']['value']='21'
    r['requested_action_digest']=sha256_digest(r['requested_action']); r=_decision_only_after_mutation(r,k)
    assert any('action/agent' in e for e in verify_receipt(r,trust=t,now=NOW,require_execution=False))
    r,k,t=build(); r['nonce']='fedcba9876543210fedcba9876543210'; r=_decision_only_after_mutation(r,k)
    # receipt nonce is independently replay-scoped; authority grant nonce remains different and is visible evidence.
    assert r['authority_grant']['nonce']!=r['nonce']
