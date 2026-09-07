"""Public adapter contracts; no credentials, network calls or DDC internals."""
from copy import deepcopy
from datetime import timezone
from .crypto import sha256_bytes, sha256_digest, b64u, public_from_private
from .model import action_core, verify_receipt, bind_execution, utc_now

def tool(kind,id,version,schema_bytes):
    return {'kind':kind,'id':id,'version':version,'schema_digest':sha256_bytes(schema_bytes)}

def mcp_action(server,name,arguments,schema_bytes,version='1'):
    return action_core(tool('mcp',server+'/'+name,version,schema_bytes),'tools/call',{'name':name,'arguments':arguments})

def http_action(method,url,body,headers=None,version='1',schema_bytes=b'http-request-v1'):
    if not url.startswith('https://'): raise ValueError('HTTPS required')
    if not isinstance(body,bytes): raise TypeError('body must be exact bytes')
    return action_core(tool('http-api',url,version,schema_bytes),method.upper(),{'url':url,'body_b64':b64u(body),'body_digest':sha256_bytes(body),'headers':headers or {}})

def github_action(repository,operation,parameters,expected_sha,version='2022-11-28'):
    if not expected_sha: raise ValueError('expected predecessor required')
    return action_core(tool('github',repository,version,b'github-rest-v1'),operation,{'repository':repository,'expected_sha':expected_sha,**parameters})

def execute_committed(receipt,*,trust,transport,executor,private_key,key_id,replay_store,now=None,parents=None):
    """Verify, reserve nonce, then pass immutable action to an explicitly supplied transport.

    The transport must enforce the actual wire request and return outcome evidence.
    A crash after reservation is UNKNOWN: reconcile externally, never blindly retry.
    """
    errors=verify_receipt(receipt,trust=trust,previous_receipts=parents,mode='preflight',require_execution=False,now=now)
    if errors: raise ValueError('; '.join(errors))
    if receipt['decision']!='ALLOW' or receipt['execution'] is not None: raise ValueError('not executable')
    if trust['execution'][key_id]!=public_from_private(private_key):
        raise ValueError('executor key not trusted')
    if trust.get('bindings',{}).get('execution',{}).get(key_id)!=executor['id']:
        raise ValueError('executor identity mismatch')
    if not replay_store.reserve(receipt['issuer']['id'],receipt['nonce'],sha256_digest(receipt)):
        raise ValueError('replay detected')
    action=deepcopy(receipt['requested_action'])
    result=transport(action)
    if not isinstance(result,dict) or 'status' not in result or 'evidence_digest' not in result:
        raise ValueError('transport must return structured outcome evidence')
    if result.get('sent_action_digest')!=sha256_digest(action):
        raise ValueError('transport missing or mismatched exact-action attestation')
    result={k:v for k,v in result.items() if k!='sent_action_digest'}
    observed=(now.astimezone(timezone.utc).isoformat().replace('+00:00','Z') if now else utc_now())
    return bind_execution(receipt,tool=action['tool'],operation=action['operation'],parameters=action['parameters'],outcome=result,executor=executor,private_key=private_key,key_id=key_id,observed_at=observed)
