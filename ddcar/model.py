"""DDCAR v0.1 reference protocol. Verification is fail-closed and side-effect free."""
from copy import deepcopy
from decimal import Decimal, InvalidOperation
import re
from datetime import datetime, timezone
from .crypto import sha256_digest, sign_obj, verify_obj
from .canonical import canonical_bytes

VERSION='0.1'
DOMAINS={'authority':'authority-v0.1','decision':'decision-v0.1','execution':'execution-v0.1'}
DECISIONS={'ALLOW','BLOCK','HUMAN-REVIEW'}
REQUIRED_DIMENSIONS=('semantic','authority','state','resource','security','physical','lineage')
SCOPE_KEYS={'max_amount','destination','currency','tool_id','operation'}

def utc_now(): return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def timestamp(s):
    if not isinstance(s,str): raise ValueError('timestamp required')
    d=datetime.fromisoformat(s.replace('Z','+00:00'))
    if d.tzinfo is None: raise ValueError('timezone required')
    return d.astimezone(timezone.utc)
def action_core(tool,operation,parameters):
    return {'tool':deepcopy(tool),'operation':operation,'parameters':deepcopy(parameters)}
def payload(r): return {k:deepcopy(v) for k,v in r.items() if k not in ('decision_proof','execution','execution_proof')}
def _sign(obj,key,kid,role):
    return {'type':'ddcar-ed25519-v1','key_id':kid,'signature':sign_obj(obj,key,DOMAINS[role])}
def _check(obj,proof,anchors,role):
    if proof['type']!='ddcar-ed25519-v1': raise ValueError('unsupported signature suite')
    pk=anchors[role][proof['key_id']]
    verify_obj(obj,proof['signature'],pk,DOMAINS[role])
    return pk

def make_receipt(*,receipt_id,nonce,agent,authority,tool,operation,parameters,evidence,policy,prerequisites,permissions,assurance,anomalies,risk,decision,issuer,previous=None,expires_at=None,issued_at=None,authority_proof=None,authority_grant=None):
    if decision not in DECISIONS: raise ValueError('invalid decision')
    action=action_core(tool,operation,parameters)
    r={'spec':'https://github.com/altrudev/DDC-Action-Receipt/blob/main/spec/DDC-ACTION-RECEIPT-v0.1.md','version':VERSION,'receipt_id':receipt_id,'issued_at':issued_at or utc_now(),'expires_at':expires_at,'nonce':nonce,'agent':agent,'authority':authority,'authority_grant':deepcopy(authority_grant),'authority_proof':deepcopy(authority_proof),'requested_action':action,'requested_action_digest':sha256_digest(action),'evidence':evidence,'policy':policy,'prerequisites':prerequisites,'permissions':permissions,'assurance':assurance,'anomalies':anomalies,'risk':risk,'decision':decision,'issuer':issuer,'lineage':{'previous':previous or [],'delegation_parent':None},'decision_proof':None,'execution':None,'execution_proof':None}
    r=deepcopy(r)
    canonical_bytes(r)
    from .schema import validate
    validate(r)
    return r

def authority_grant(principal,scope,expires_at,nonce,issued_at=None,agent=None,action_digest=None,delegation_parent=None):
    return {'principal':principal,'scope':deepcopy(scope),'expires_at':expires_at,'nonce':nonce,'issued_at':issued_at or utc_now(),'agent':agent,'action_digest':action_digest,'delegation_parent':delegation_parent}
def sign_authority(grant,key,key_id): return _sign(grant,key,key_id,'authority')
def seal_decision(r,key,key_id):
    r=deepcopy(r)
    if r['decision_proof'] or r['execution']: raise ValueError('already sealed')
    from .schema import validate
    validate(r)
    r['decision_proof']=_sign(payload(r),key,key_id,'decision')
    return r

def execution_payload(r): return {'decision_digest':sha256_digest(payload(r)),'decision_proof':r['decision_proof'],'execution':r['execution']}
def bind_execution(r,*,tool,operation,parameters,outcome,executor,private_key,key_id,observed_at=None):
    r=deepcopy(r)
    if r['decision']!='ALLOW' or not r['decision_proof'] or r['execution'] is not None: raise ValueError('not an unexecuted ALLOW commitment')
    exact=action_core(tool,operation,parameters)
    if sha256_digest(exact)!=r['requested_action_digest']: raise ValueError('action substitution')
    r['execution']={'exact_action':exact,'exact_action_digest':sha256_digest(exact),'outcome':outcome,'executor':executor,'observed_at':observed_at or utc_now()}
    r['execution_proof']=_sign(execution_payload(r),private_key,key_id,'execution')
    return r

def receipt_digest(r): return sha256_digest(r)

def _scope_contains(parent,child):
    """Conservative scope subset: exact fields, explicit decimal ceilings only."""
    if isinstance(parent,dict) and isinstance(child,dict):
        if not all(k in child for k in parent): return False
        for k,p in parent.items():
            v=child[k]
            if k.startswith('max_'):
                try:
                    if not isinstance(p,str) or not isinstance(v,str): return False
                    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',p) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',v): return False
                    a,b=Decimal(p),Decimal(v)
                    if not a.is_finite() or not b.is_finite() or a<0 or b<0 or b>a: return False
                except InvalidOperation: return False
            elif not _scope_contains(p,v): return False
        return True
    if isinstance(parent,list) and isinstance(child,list):
        return all(any(_scope_contains(p,c) for p in parent) for c in child)
    return type(parent)==type(child) and parent==child

def _action_within_scope(action,scope):
    """Known payment constraints. Unknown constraints require an external policy engine."""
    params=action['parameters']
    if not scope or set(scope)-SCOPE_KEYS: return False
    if not {'tool_id','operation'}.issubset(scope): return False
    if scope.get('tool_id',action['tool']['id'])!=action['tool']['id']: return False
    if scope.get('operation',action['operation'])!=action['operation']: return False
    if 'max_amount' in scope:
        try:
            if not isinstance(params['amount'],str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',params['amount']): return False
            amount=Decimal(params['amount']); limit=Decimal(scope['max_amount'])
            if not amount.is_finite() or amount<0 or amount>limit: return False
        except (KeyError,InvalidOperation,TypeError,ValueError): return False
    if 'destination' in scope and params.get('to')!=scope['destination']: return False
    if 'currency' in scope and params.get('currency')!=scope['currency']: return False
    return True

def verify_receipt(r,*,trust=None,previous_receipts=None,seen_nonces=None,now=None,mode='historical',require_execution=True,external_evidence=None,_visited=None,_memo=None,_budget=None):
    errors=[]
    def fail(s):
        if len(errors)<64: errors.append(str(s)[:512])
    try:
        canonical_bytes(r)
        from .schema import validate
        validate(r)
    except Exception as e: return ['schema/canonicalization: '+str(e)]
    trust=trust or {}; now=now or datetime.now(timezone.utc)
    if _memo is None: _memo={}
    if _budget is None: _budget=[0]
    visited=_visited or frozenset()
    digest=receipt_digest(r)
    if digest in visited: return ['lineage cycle']
    cache_key=(digest,mode,require_execution)
    cacheable=seen_nonces is None and external_evidence is None
    if cacheable and cache_key in _memo: return list(_memo[cache_key])
    if _budget[0]>=256: return ['lineage verification work limit exceeded']
    _budget[0]+=1
    if _visited is None and previous_receipts is not None:
        if not isinstance(previous_receipts,dict) or len(previous_receipts)>64:
            return ['lineage parent count exceeded']
        try:
            if sum(len(canonical_bytes(p)) for p in previous_receipts.values())>16*1024*1024:
                return ['lineage parent bytes exceeded']
        except Exception as e: return ['lineage parent canonicalization: '+str(e)]
    if mode not in ('historical','preflight'): return ['unsupported verification mode']
    if now.tzinfo is None: return ['verifier clock must be timezone-aware']
    try:
        if not r['authority_grant'] or not r['authority_proof']: fail('missing independently signed authority grant')
        else:
            _check(r['authority_grant'],r['authority_proof'],trust,'authority')
            g=r['authority_grant']; a=r['authority']
            if g['principal']!=a['principal'] or not _scope_contains(g['scope'],a['scope']): fail('authority scope/principal mismatch')
            if g['agent']!=r['agent']['id'] or g['action_digest']!=r['requested_action_digest']: fail('authority grant action/agent mismatch')
            if trust.get('bindings',{}).get('authority',{}).get(r['authority_proof']['key_id'])!=g['principal']: fail('authority key is not bound to principal')
            if timestamp(g['issued_at'])>timestamp(r['issued_at']): fail('authority grant issued after decision')
            if r['expires_at'] and timestamp(r['expires_at'])>timestamp(g['expires_at']): fail('receipt exceeds grant expiry')
            if timestamp(r['issued_at'])>timestamp(g['expires_at']): fail('authority expired at decision')
            if g['delegation_parent']!=r['lineage']['delegation_parent']: fail('delegation parent mismatch')
    except Exception as e: fail('authority proof: '+str(e))
    try:
        if trust.get('bindings',{}).get('decision',{}).get(r['decision_proof']['key_id'])!=r['issuer']['id']: fail('decision key is not bound to issuer')
        _check(payload(r),r['decision_proof'],trust,'decision')
    except Exception as e: fail('decision signature/trust: '+str(e))
    if not _action_within_scope(r['requested_action'],r['authority']['scope']): fail('requested action exceeds authority scope')
    if sha256_digest(r['requested_action'])!=r['requested_action_digest']: fail('requested action digest mismatch')
    decision=r['decision']; ex=r['execution']
    if decision!='ALLOW' and ex is not None: fail('non-ALLOW execution')
    if decision=='ALLOW' and r['expires_at'] is None: fail('ALLOW requires bounded expiry')
    if decision=='ALLOW' and require_execution and ex is None: fail('missing execution')
    if ex is None and r['execution_proof'] is not None: fail('orphan execution signature')
    if ex is not None and r['execution_proof'] is None: fail('missing execution signature')
    if ex is not None:
        if decision!='ALLOW': fail('execution without ALLOW')
        if sha256_digest(ex['exact_action'])!=ex['exact_action_digest'] or ex['exact_action_digest']!=r['requested_action_digest']: fail('parameter/action substitution')
        try:
            dp=trust['decision'][r['decision_proof']['key_id']]; ep=trust['execution'][r['execution_proof']['key_id']]
            if dp==ep: fail('decision/execution keys are not independent')
            if trust.get('bindings',{}).get('execution',{}).get(r['execution_proof']['key_id'])!=ex['executor']['id']: fail('execution key is not bound to executor')
            _check(execution_payload(r),r['execution_proof'],trust,'execution')
        except Exception as e: fail('execution signature/trust: '+str(e))
    try:
        issued=timestamp(r['issued_at']); cutoff=timestamp(ex['observed_at']) if ex else issued
        if cutoff<issued: fail('execution precedes decision')
        if r['expires_at'] and cutoff>timestamp(r['expires_at']): fail('authorization stale at execution')
        if r['authority_grant'] and cutoff>timestamp(r['authority_grant']['expires_at']): fail('human authority stale at execution')
        if r['authority_grant'] and timestamp(r['authority_grant']['issued_at'])>issued: fail('authority not yet issued at decision')
        if mode=='preflight' and r['expires_at'] and now>timestamp(r['expires_at']): fail('authorization expired now')
        if mode=='preflight' and r['authority_grant'] and now>timestamp(r['authority_grant']['expires_at']): fail('human authority expired now')
        if cutoff>now: fail('event in the future relative to verifier clock')
        for i,ev in enumerate(r['evidence']):
            if timestamp(ev['observed_at'])>issued or cutoff>timestamp(ev['valid_until']): fail('stale evidence at index '+str(i))
            if external_evidence is not None:
                data=external_evidence.get(ev['digest'])
                if data is None: fail('missing external evidence '+ev['digest'])
                else:
                    from .crypto import sha256_bytes
                    if sha256_bytes(data)!=ev['digest']: fail('external evidence digest mismatch')
    except Exception as e: fail('time/evidence: '+str(e))
    if r['decision']=='ALLOW':
        if not r['evidence']: fail('ALLOW without observed evidence')
        if not r['permissions'] or not r['prerequisites']: fail('ALLOW without explicit permission/prerequisite checks')
        if not r['authority_grant'] or not r['authority_proof']: fail('ALLOW without human authority proof')
        if any(r['assurance'].get(d,{}).get('status')!='PASS' for d in REQUIRED_DIMENSIONS): fail('ALLOW without required assurance dimensions')
        if any(x.get('status')!='PASS' for d,x in r['assurance'].items() if d!='frequency') or any(x.get('status')!='PASS' for x in r['prerequisites']+r['permissions']): fail('ALLOW with failed constraints')
    if seen_nonces is not None and (r['issuer']['id']+'\0'+r['nonce']) in seen_nonces: fail('replay detected')
    if r['lineage']['delegation_parent'] and r['lineage']['delegation_parent'] not in r['lineage']['previous']: fail('delegation parent not in lineage')
    if previous_receipts is None and r['lineage']['previous']: fail('lineage parents not supplied')
    if previous_receipts is not None:
        if len(visited)>=64: fail('lineage depth exceeded'); return errors
        for d in r['lineage']['previous']:
            parent=previous_receipts.get(d)
            if parent is None: fail('missing lineage parent '+d); continue
            if receipt_digest(parent)!=d: fail('forged lineage parent '+d); continue
            pe=verify_receipt(parent,trust=trust,previous_receipts=previous_receipts,now=now,require_execution=True,_visited=visited|{digest},_memo=_memo,_budget=_budget)
            if pe: fail('invalid lineage parent '+d+': '+'; '.join(pe))
            try:
                if d==r['lineage']['delegation_parent']:
                    if not _scope_contains(parent['authority']['scope'],r['authority']['scope']): fail('delegation expands authority')
                    if not parent['expires_at'] or not r['expires_at'] or timestamp(parent['expires_at'])<timestamp(r['expires_at']): fail('delegation exceeds parent expiry')
                    if parent['agent']['id']==r['agent']['id']: fail('self-delegation')
                if timestamp(parent['issued_at'])>timestamp(r['issued_at']): fail('lineage time inversion')
            except Exception as e: fail('lineage: '+str(e))
    if not errors and cacheable: _memo[cache_key]=()
    return errors
