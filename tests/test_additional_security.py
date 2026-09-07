from copy import deepcopy
from datetime import datetime, timezone
import pytest
from test_protocol import fixture, verify, seal_again, NOW
from ddcar.model import verify_receipt, receipt_digest
from ddcar.crypto import sha256_digest, sign_obj


def test_allow_cannot_omit_expiry():
    r,k,t=fixture(); r['expires_at']=None; r=seal_again(r,k)
    assert verify(r,t,require_execution=False)


def test_unknown_authority_scope_is_not_implicitly_unrestricted():
    r,k,t=fixture(); r['authority']['scope']={}; r=seal_again(r,k)
    assert verify(r,t,require_execution=False)


def test_delegation_requires_parent_authority_for_child_agent():
    p,k,t=fixture(); r=deepcopy(p); r['receipt_id']='child'; r['nonce']='c'*32
    r['agent']={'id':'agent:child'}; r['authority_grant']['agent']='agent:child'
    r['lineage']['previous']=[receipt_digest(p)]; r['lineage']['delegation_parent']=receipt_digest(p)
    r['authority_grant']['delegation_parent']=receipt_digest(p)
    r['authority_proof']={'type':'ddcar-ed25519-v1','key_id':'authority-key','signature':sign_obj(r['authority_grant'],k['authority'][0],'authority-v0.1')}
    r=seal_again(r,k)
    assert verify(r,t,previous_receipts={receipt_digest(p):p},require_execution=False)==[]


def test_scope_cannot_drop_parent_limit():
    r,k,t=fixture(); r['authority']['scope'].pop('max_amount'); r=seal_again(r,k)
    assert any('scope' in e for e in verify(r,t,require_execution=False))


def test_delegation_cannot_drop_parent_limit():
    p,k,t=fixture(); r=deepcopy(p); r['receipt_id']='child'; r['nonce']='c'*32
    r['agent']={'id':'agent:child'}; r['authority_grant']['agent']='agent:child'
    r['authority']['scope'].pop('max_amount'); r['authority_grant']['scope'].pop('max_amount')
    r['lineage']['previous']=[receipt_digest(p)]; r['lineage']['delegation_parent']=receipt_digest(p)
    r['authority_grant']['delegation_parent']=receipt_digest(p)
    r['authority_proof']={'type':'ddcar-ed25519-v1','key_id':'authority-key','signature':sign_obj(r['authority_grant'],k['authority'][0],'authority-v0.1')}
    r=seal_again(r,k)
    assert any('delegation expands' in e for e in verify(r,t,previous_receipts={receipt_digest(p):p},require_execution=False))
