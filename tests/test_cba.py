import copy
import unittest
from ddcar.cba import analyze, benchmark, digest

BASE = {'identity':'worker-a','authority':'grant-1','action':{'operation':'inspect','path':'/workspace'},'policy':'p2','state':'ready','result':'ok'}
POLICY = {'critical':list(BASE), 'text_fields':['action'], 'required_boundaries':['identity','authority','representation','policy','state','execution','observation','evidence'], 'maximum_age':10}
BOUNDARIES = POLICY['required_boundaries']

def events():
    return [dict(boundary=b, sequence=i, observed=copy.deepcopy(BASE), trusted=True, time=i, nonce='n'+str(i)) for i,b in enumerate(BOUNDARIES)]

def case(name, mutate=None, expected=True):
    ev=events()
    if mutate: mutate(ev)
    return {'name':name,'commitment':BASE,'events':ev,'policy':POLICY,'expected':expected}

def fixtures():
    return [
        case('clean',expected=False),
        case('CBA-001 authority substitution',lambda e:e[1]['observed'].update(authority='grant-2')),
        case('CBA-002 parameter divergence',lambda e:e[5]['observed']['action'].update(path='/other')),
        case('CBA-003 representation ambiguity',lambda e:e[2]['observed']['action'].update(path='/work\u200bspace')),
        case('CBA-004 policy downgrade',lambda e:e[3]['observed'].update(policy='p1')),
        case('CBA-005 state drift',lambda e:e[4]['observed'].update(state='changed')),
        case('CBA-006 replay',lambda e:e[6].update(nonce=e[0]['nonce'])),
        case('CBA-007 worker substitution',lambda e:e[5]['observed'].update(identity='worker-b')),
        case('CBA-008 evidence divergence',lambda e:e[7]['observed'].update(result='altered')),
        case('CBA-009 compound chain',lambda e:(e[2]['observed'].update(policy='p1'),e[5]['observed'].update(authority='grant-2'))),
        case('CBA-010 temporal anomaly',lambda e:e[4].update(time=100)),
    ]

class CBATests(unittest.TestCase):
    def test_fixtures(self):
        for c in fixtures():
            with self.subTest(c['name']):
                r=analyze(c['commitment'],c['events'],policy=c['policy'])
                self.assertEqual(r['disposition']=='DIVERGENT',c['expected'])
                self.assertEqual(r['authorization'],'NOT_EVALUATED')
    def test_benchmark(self):
        r=benchmark(fixtures(),repetitions=2)
        self.assertEqual((r['tp'],r['fn'],r['fp'],r['tn']),(10,0,0,1))
    def test_untrusted_is_not_accepted(self):
        e=events(); e[0]['trusted']=False
        self.assertIn('UNTRUSTED_OBSERVATION',analyze(BASE,e,policy=POLICY)['counts'])
    def test_missing_fields_fail(self):
        e=events(); del e[0]['observed']['authority']
        self.assertIn('MISSING_CRITICAL',analyze(BASE,e,policy=POLICY)['counts'])
    def test_missing_boundary(self):
        self.assertIn('MISSING_BOUNDARY',analyze(BASE,events()[:-1],policy=POLICY)['counts'])
    def test_noncritical_changes(self):
        e=events(); e[0]['observed']['diagnostic']='ignored'
        self.assertEqual(analyze(BASE,e,policy=POLICY)['disposition'],'CONSISTENT')
    def test_unicode(self):
        for text,code in [('e\u0301','NON_NFC'),('\u202e','BIDI_CONTROL'),('\ufb01','COMPATIBILITY_NORMALIZATION')]:
            e=events(); e[0]['observed']['action']['path']=text
            self.assertIn(code,analyze(BASE,e,policy=POLICY)['counts'])
    def test_determinism(self):
        self.assertEqual(analyze(BASE,events(),policy=POLICY),analyze(BASE,events(),policy=POLICY))
    def test_input_immutability(self):
        e=events(); before=copy.deepcopy(e)
        analyze(BASE,e,policy=POLICY)
        self.assertEqual(e,before)
    def test_bad_inputs(self):
        for obj in [float('nan'),2**60,{'x':float('inf')}]:
            with self.assertRaises(ValueError): digest(obj)
        with self.assertRaises(ValueError): analyze(BASE,events()*33,policy=POLICY)
        with self.assertRaises(ValueError): analyze(BASE,events(),policy={'unknown':True})
        with self.assertRaises(ValueError): analyze(BASE,[{'boundary':'identity'}])
    def test_reorder(self):
        e=events(); e[1]['sequence']=0
        self.assertIn('SEQUENCE_REORDER',analyze(BASE,e,policy=POLICY)['counts'])
    def test_baseline_is_explicit(self):
        e=events(); changed=copy.deepcopy(BASE); changed['authority']='other'
        r=analyze(changed,e,policy=POLICY,trusted_baseline=BASE)
        self.assertIn('COMMITMENT_DIVERGENCE',r['counts'])

if __name__=='__main__': unittest.main()
