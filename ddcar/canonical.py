"""DDCAR-CJ1: RFC 8785-compatible canonical JSON restricted to safe integers."""
import json

MAX_BYTES = 4 * 1024 * 1024

class CanonicalizationError(ValueError):
    pass

def _encode(v, depth=0):
    if depth > 64:
        raise CanonicalizationError('maximum depth exceeded')
    if v is None or isinstance(v, (bool, str)):
        if isinstance(v, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise CanonicalizationError('unpaired surrogate')
        return json.dumps(v, ensure_ascii=False, separators=(',', ':'))
    if type(v) is int:
        if not -(2**53)+1 <= v <= 2**53-1:
            raise CanonicalizationError('integer outside interoperable range')
        return str(v)
    if isinstance(v, list):
        return '['+','.join(_encode(x, depth+1) for x in v)+']'
    if isinstance(v, dict):
        if not all(isinstance(k,str) for k in v):
            raise CanonicalizationError('non-string key')
        keys=sorted(v,key=lambda k:k.encode('utf-16be'))
        return '{'+','.join(_encode(k,depth+1)+':'+_encode(v[k],depth+1) for k in keys)+'}'
    raise CanonicalizationError('unsupported JSON value; encode decimals as strings')

def canonical_bytes(obj):
    data=_encode(obj).encode('utf-8')
    if len(data)>MAX_BYTES: raise CanonicalizationError('receipt exceeds size limit')
    return data

def loads(data):
    if isinstance(data,(bytes,bytearray)):
        if len(data)>MAX_BYTES: raise CanonicalizationError('receipt exceeds size limit')
        data=data.decode('utf-8',errors='strict')
    elif len(data.encode('utf-8'))>MAX_BYTES:
        raise CanonicalizationError('receipt exceeds size limit')
    def pairs(items):
        d={}
        for k,v in items:
            if k in d: raise CanonicalizationError('duplicate key: '+k)
            d[k]=v
        return d
    def reject(x): raise CanonicalizationError('non-integer number: '+x)
    obj=json.loads(data,object_pairs_hook=pairs,parse_float=reject,parse_constant=reject)
    canonical_bytes(obj)
    return obj
