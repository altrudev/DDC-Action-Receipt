"""Generate disposable signed public examples. No live payments or network access."""
import json
from pathlib import Path
from ddcar.crypto import generate_keypair, sha256_digest, sha256_bytes
from ddcar.model import action_core, authority_grant, sign_authority, make_receipt, seal_decision, bind_execution, REQUIRED_DIMENSIONS

OUT=Path(__file__).parent
T='2026-09-06T12:00:00Z'; E='2026-09-06T13:00:00Z'
keys={role:generate_keypair() for role in ('authority','decision','execution')}
trust={role:{role+'-key':pair[1]} for role,pair in keys.items()}
trust['bindings']={'authority':{'authority-key':'human:demo'},'decision':{'decision-key':'gate:demo'},'execution':{'execution-key':'executor:demo'}}
tool={'kind':'api','id':'bank:demo','version':'1','schema_digest':sha256_digest('demo-schema')}
params={'amount':'10.00','currency':'CAD','to':'merchant:demo'}
action=action_core(tool,'transfer',params)
scope={'max_amount':'25.00','currency':'CAD','destination':'merchant:demo','tool_id':'bank:demo','operation':'transfer'}
grant=authority_grant('human:demo',scope,E,'a'*32,issued_at=T,agent='agent:demo',action_digest=sha256_digest(action))
proof=sign_authority(grant,keys['authority'][0],'authority-key')
r=make_receipt(receipt_id='demo-1',nonce='b'*32,agent={'id':'agent:demo'},authority={'kind':'human','principal':'human:demo','basis':'explicit-approval','scope':scope},authority_grant=grant,authority_proof=proof,tool=tool,operation='transfer',parameters=params,evidence=[{'type':'state','digest':sha256_bytes(b'demo-state'),'observed_at':T,'valid_until':E}],policy={'id':'demo-policy','version':'1','digest':sha256_digest('demo-policy')},prerequisites=[{'status':'PASS'}],permissions=[{'status':'PASS'}],assurance={d:{'status':'PASS'} for d in REQUIRED_DIMENSIONS},anomalies=[],risk={'class':'low'},decision='ALLOW',issuer={'id':'gate:demo'},expires_at=E,issued_at=T)
r=seal_decision(r,keys['decision'][0],'decision-key')
r=bind_execution(r,tool=tool,operation='transfer',parameters=params,outcome={'status':'SUCCEEDED','evidence_digest':sha256_digest('simulated-result')},executor={'id':'executor:demo'},private_key=keys['execution'][0],key_id='execution-key',observed_at='2026-09-06T12:05:00Z')
for name,obj in [('receipt.json',r),('trust.json',trust)]:
    (OUT/name).write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print('Generated disposable public examples; no private keys persisted.')
