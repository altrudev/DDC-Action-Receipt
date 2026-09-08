from copy import deepcopy
from datetime import datetime, timezone
from test_protocol import fixture, seal_again, NOW
from ddcar.model import verify_receipt


def test_preflight_rejects_evidence_expired_after_decision():
    receipt, keys, trust = fixture()
    receipt = seal_again(receipt, keys)
    receipt['evidence'][0]['valid_until'] = '2026-09-06T12:10:00Z'
    receipt = seal_again(receipt, keys)
    assert verify_receipt(receipt, trust=trust, now=NOW,
                          mode='historical', require_execution=False) == []
    errors = verify_receipt(receipt, trust=trust, now=NOW,
                            mode='preflight', require_execution=False)
    assert any('stale evidence' in error for error in errors)


def test_preflight_accepts_fresh_evidence_at_current_time():
    receipt, keys, trust = fixture()
    receipt = seal_again(receipt, keys)
    assert verify_receipt(receipt, trust=trust, now=NOW,
                          mode='preflight', require_execution=False) == []


def test_historical_execution_does_not_expire_retroactively():
    receipt, keys, trust = fixture()
    receipt['evidence'][0]['valid_until'] = '2026-09-06T12:10:00Z'
    # Re-sign the decision while preserving the original execution commitment.
    receipt['decision_proof'] = None
    receipt['execution'] = None
    receipt['execution_proof'] = None
    receipt = seal_again(receipt, keys)
    from ddcar.model import bind_execution
    receipt = bind_execution(receipt, tool=receipt['requested_action']['tool'],
        operation=receipt['requested_action']['operation'],
        parameters=receipt['requested_action']['parameters'],
        outcome={'status':'SUCCEEDED','evidence_digest':receipt['evidence'][0]['digest']},
        executor={'id':'exec:e'}, private_key=keys['execution'][0],
        key_id='execution-key', observed_at='2026-09-06T12:05:00Z')
    assert verify_receipt(receipt, trust=trust,
        now=datetime(2030,1,1,tzinfo=timezone.utc), mode='historical') == []
