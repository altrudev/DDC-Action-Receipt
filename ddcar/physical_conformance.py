"""DDCAR v0.3 physical conformance runner.

Consumes the shared Physical Gate vector, constructs independently signed DDCAR
authority/decision/execution evidence, and returns a machine-readable verification
report. It has no hardware side effects.
"""
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from .crypto import generate_keypair, sha256_digest, sha256_bytes
from .model import (
    REQUIRED_DIMENSIONS, authority_grant, sign_authority, make_receipt,
    seal_decision, bind_execution, verify_receipt, receipt_digest,
)

T='1970-01-01T00:16:40Z'
E='1970-01-01T00:16:41Z'
EXEC='1970-01-01T00:16:40.250000Z'
NOW=datetime(1970,1,1,0,16,40,500000,tzinfo=timezone.utc)

def load_vector(path=None):
    path=Path(path) if path else Path(__file__).resolve().parents[1]/'conformance'/'ddcar-physical-v0.3.json'
    return json.loads(path.read_text())

def build_receipt(vector=None):
    v=deepcopy(vector or load_vector())
    keys={role:generate_keypair() for role in ('authority','decision','execution')}
    trust={role:{role+'-key':pair[1]} for role,pair in keys.items()}
    trust['bindings']={
      'authority':{'authority-key':'human:owner'},
      'decision':{'decision-key':'ddc-physical-gate'},
      'execution':{'execution-key':'sim:executor'},
    }
    action=v['action']; scope=v['scope']
    grant=authority_grant('human:owner',scope,E,v['nonce'],issued_at=T,
      agent=v['agent'],action_digest=sha256_digest(action))
    proof=sign_authority(grant,keys['authority'][0],'authority-key')
    receipt=make_receipt(
      receipt_id='physical-v03-vector-0001',nonce=v['nonce'],agent={'id':v['agent']},
      authority={'kind':'human','principal':'human:owner','basis':'shared-conformance-vector','scope':scope},
      authority_grant=grant,authority_proof=proof,tool=action['tool'],operation=action['operation'],
      parameters=action['parameters'],
      evidence=[{'type':'physical-state','digest':sha256_bytes(b'v03-state'),
        'observed_at':T,'valid_until':E,'source':'simulator:arm-01'}],
      policy={'id':'ddc-physical-gate','version':'0.3','digest':sha256_digest(v['profile_digest'])},
      prerequisites=[{'status':'PASS','claim':'physical deterministic gate completed'}],
      permissions=[{'status':'PASS','claim':'signed authority scope permits exact action'}],
      assurance={d:{'status':'PASS','claim':'v0.3 conformance evidence'} for d in REQUIRED_DIMENSIONS},
      anomalies=[],risk={'class':'medium'},decision='ALLOW',issuer={'id':'ddc-physical-gate'},
      expires_at=E,issued_at=T)
    receipt=seal_decision(receipt,keys['decision'][0],'decision-key')
    receipt=bind_execution(receipt,tool=action['tool'],operation=action['operation'],
      parameters=action['parameters'],outcome={'status':'SUCCEEDED','evidence_digest':sha256_digest('simulated-v03')},
      executor={'id':'sim:executor'},private_key=keys['execution'][0],key_id='execution-key',observed_at=EXEC)
    return receipt,keys,trust

def run(vector=None):
    receipt,keys,trust=build_receipt(vector)
    errors=verify_receipt(receipt,trust=trust,now=NOW)
    return {
      'schema':'ddcar-physical-conformance/0.3',
      'status':'PASS' if not errors else 'FAIL',
      'errors':errors,
      'receipt_digest':receipt_digest(receipt),
      'requested_action_digest':receipt['requested_action_digest'],
      'decision':receipt['decision'],
      'execution_status':receipt['execution']['outcome']['status'],
      'scope':deepcopy(receipt['authority']['scope']),
      'limitations':[
        'simulation-only',
        'does not establish certified functional safety',
        'does not independently establish physical-world outcome',
      ],
    }
