"""Bounded DAG verification: shared ancestors must not cause exponential work."""
from copy import deepcopy
from ddcar.crypto import sha256_digest
from ddcar.model import receipt_digest, seal_decision, bind_execution, verify_receipt
from test_protocol import fixture, NOW

def chain(count, corrupt=False):
    base,keys,trust=fixture()
    nodes=[]; parents={}
    for i in range(count):
        r=deepcopy(base)
        r['receipt_id']='dag-'+str(i)
        r['nonce']=format(i,'032x')
        r['lineage']['previous']=[receipt_digest(x) for x in nodes]
        r['decision_proof']=None; r['execution']=None; r['execution_proof']=None
        r=seal_decision(r,keys['decision'][0],'decision-key')
        a=r['requested_action']
        r=bind_execution(r,tool=a['tool'],operation=a['operation'],parameters=a['parameters'],
            outcome={'status':'SUCCEEDED','evidence_digest':sha256_digest('result')},
            executor={'id':'exec:e'},private_key=keys['execution'][0],key_id='execution-key',
            observed_at='2026-09-06T12:05:00Z')
        if corrupt and i==0: r['risk']['class']='high'
        nodes.append(r)
        parents[receipt_digest(r)]=r
    return nodes[-1],{k:v for k,v in parents.items() if v is not nodes[-1]},trust

def test_shared_ancestor_dag_is_bounded():
    r,parents,trust=chain(20)
    budget=[0]
    assert verify_receipt(r,trust=trust,previous_receipts=parents,now=NOW,_budget=budget)==[]
    assert budget[0]<=20

def test_invalid_shared_ancestor_fails_with_bounded_work():
    r,parents,trust=chain(14,corrupt=True)
    budget=[0]
    errors=verify_receipt(r,trust=trust,previous_receipts=parents,now=NOW,_budget=budget)
    assert errors
    assert budget[0]<=256
    assert len(errors)<=64
    assert all(len(e)<=512 for e in errors)

def test_parent_count_limit():
    r,parents,trust=chain(2)
    for i in range(65): parents[sha256_digest(i)]=r
    assert any('count exceeded' in e for e in verify_receipt(r,trust=trust,previous_receipts=parents,now=NOW))
