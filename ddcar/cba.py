"""CBA/0.1: deterministic, side-effect-free cross-boundary shadow assurance.

This module does not authorize execution or establish trust in evidence producers.
"""
import hashlib
import json
import time
import unicodedata
from collections import Counter
from copy import deepcopy

PROFILE = 'ddc-cba/0.1'
BOUNDARIES = ('identity', 'authority', 'representation', 'policy', 'state', 'execution', 'observation', 'evidence')
MAX_EVENTS = 256
MAX_BYTES = 1024 * 1024


def _canonical(obj):
    def check(v, depth=0):
        if depth > 32:
            raise ValueError('maximum depth exceeded')
        if v is None or type(v) in (bool, int, str):
            if type(v) is int and abs(v) > 2**53-1:
                raise ValueError('integer outside interoperable range')
            if isinstance(v, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in v):
                raise ValueError('unpaired surrogate')
            return
        if isinstance(v, list):
            for x in v: check(x, depth+1)
        elif isinstance(v, dict) and all(isinstance(k, str) for k in v):
            for k, x in v.items():
                check(k, depth+1); check(x, depth+1)
        else:
            raise ValueError('unsupported JSON value')
    check(obj)
    data = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    if len(data) > MAX_BYTES:
        raise ValueError('input exceeds size limit')
    return data


def digest(obj):
    return 'sha256:' + hashlib.sha256(_canonical(obj)).hexdigest()


def _issue(code, boundary, event, detail=''):
    return {'code': code, 'boundary': boundary, 'event': event, 'detail': detail}


def _text_risks(value):
    risks = set()
    if not isinstance(value, str): return []
    if unicodedata.normalize('NFC', value) != value: risks.add('NON_NFC')
    if unicodedata.normalize('NFKC', value) != value: risks.add('COMPATIBILITY_NORMALIZATION')
    for ch in value:
        cp = ord(ch)
        if unicodedata.category(ch) == 'Cf' or cp in (0x034F, 0x180E):
            risks.add('INVISIBLE_FORMAT')
        if cp in range(0x202A, 0x202F) or cp in range(0x2066, 0x206A):
            risks.add('BIDI_CONTROL')
    return sorted(risks)


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _walk_strings(k)
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for v in value: yield from _walk_strings(v)


def analyze(commitment, events, *, policy=None, trusted_baseline=None):
    """Compare observations with a caller-supplied immutable baseline.

    Evidence and signatures must be verified independently before their values are
    marked trusted. A positive report is not an authorization or execution permit.
    """
    if policy is None:
        raise ValueError('explicit policy required')
    if not isinstance(policy, dict) or set(policy)-{'critical', 'text_fields', 'maximum_age', 'required_boundaries'}:
        raise ValueError('unsupported policy')
    critical = policy.get('critical', [])
    text_fields = policy.get('text_fields', [])
    required = policy.get('required_boundaries', [])
    if not isinstance(critical, list) or not critical or not isinstance(text_fields, list) or not isinstance(required, list) or not required:
        raise ValueError('critical and required boundary lists required')
    if not all(isinstance(x, str) for x in critical + text_fields + required):
        raise ValueError('invalid policy fields')
    if any(x not in BOUNDARIES for x in required): raise ValueError('unknown boundary')
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError('event limit exceeded')
    if not isinstance(commitment, dict): raise ValueError('invalid commitment')
    if any(x not in commitment for x in critical): raise ValueError('missing baseline field')
    _canonical({'commitment': commitment, 'events': events, 'policy': policy})
    baseline = deepcopy(trusted_baseline if trusted_baseline is not None else commitment)
    _canonical(baseline)
    if not isinstance(baseline, dict): raise ValueError('invalid baseline')
    issues, traces, seen = [], [], set()
    if trusted_baseline is not None and digest(commitment) != digest(baseline):
        issues.append(_issue('COMMITMENT_DIVERGENCE', 'authority', -1))
    previous_sequence = -1
    previous_time = None
    nonces = set()
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {'boundary', 'sequence', 'observed', 'trusted', 'time', 'nonce'}:
            raise ValueError('invalid event shape')
        boundary, seq = event['boundary'], event['sequence']
        if boundary not in BOUNDARIES or type(seq) is not int or seq < 0:
            raise ValueError('invalid boundary or sequence')
        if type(event['trusted']) is not bool or not isinstance(event['observed'], dict):
            raise ValueError('invalid observation')
        t, nonce = event['time'], event['nonce']
        if type(t) is not int or t < 0 or not isinstance(nonce, str) or not nonce:
            raise ValueError('invalid time or nonce')
        if seq <= previous_sequence: issues.append(_issue('SEQUENCE_REORDER', boundary, index))
        if previous_time is not None and t < previous_time: issues.append(_issue('TIME_REORDER', boundary, index))
        if nonce in nonces: issues.append(_issue('REPLAY', boundary, index))
        if not event['trusted']: issues.append(_issue('UNTRUSTED_OBSERVATION', boundary, index))
        if 'maximum_age' in policy:
            age = policy['maximum_age']
            if type(age) is not int or age < 0: raise ValueError('invalid maximum age')
            if previous_time is not None and t - previous_time > age:
                issues.append(_issue('STATE_STALE', boundary, index))
        previous_sequence, previous_time = seq, t
        nonces.add(nonce); seen.add(boundary)
        observed = event['observed']
        if any(x not in observed for x in critical):
            issues.append(_issue('INCOMPLETE_OBSERVATION', boundary, index))
        for field in critical:
            if field not in baseline or field not in observed:
                issues.append(_issue('MISSING_CRITICAL', boundary, index, field))
            elif digest(baseline[field]) != digest(observed[field]):
                issues.append(_issue('CRITICAL_DIVERGENCE', boundary, index, field))
        for field in text_fields:
            if field in observed:
                for value in _walk_strings(observed[field]):
                    for risk in _text_risks(value):
                        issues.append(_issue(risk, boundary, index, field))
        traces.append({'boundary': boundary, 'sequence': seq, 'observation_digest': digest(observed), 'trusted': event['trusted']})
    for boundary in required:
        if boundary not in seen: issues.append(_issue('MISSING_BOUNDARY', boundary, -1))
    counts = dict(sorted(Counter(x['code'] for x in issues).items()))
    return {'profile': PROFILE, 'mode': 'shadow', 'commitment_digest': digest(commitment),
            'baseline_digest': digest(baseline), 'policy_digest': digest(policy),
            'event_count': len(events), 'issue_count': len(issues), 'issues': issues,
            'counts': counts, 'traces': traces,
            'disposition': 'DIVERGENT' if issues else 'CONSISTENT',
            'authorization': 'NOT_EVALUATED'}


def benchmark(cases, *, repetitions=100):
    """Controlled comparison; timing is diagnostic, not an authorization signal."""
    if type(repetitions) is not int or not 1 <= repetitions <= 10000:
        raise ValueError('invalid repetitions')
    results = []
    for case in cases:
        start = time.perf_counter_ns()
        for _ in range(repetitions):
            report = analyze(case['commitment'], case['events'], policy=case.get('policy'))
        elapsed = time.perf_counter_ns() - start
        results.append({'name': case['name'], 'expected': case['expected'],
                        'detected': report['disposition'] == 'DIVERGENT',
                        'mean_ns': elapsed // repetitions,
                        'report_bytes': len(_canonical(report)), 'issue_count': report['issue_count']})
    tp = sum(r['expected'] and r['detected'] for r in results)
    fn = sum(r['expected'] and not r['detected'] for r in results)
    fp = sum(not r['expected'] and r['detected'] for r in results)
    tn = sum(not r['expected'] and not r['detected'] for r in results)
    return {'profile': PROFILE, 'repetitions': repetitions, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn, 'cases': results}
