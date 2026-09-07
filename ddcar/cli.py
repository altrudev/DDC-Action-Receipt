import argparse, json, sys
from pathlib import Path
from .canonical import canonical_bytes, loads
from .crypto import generate_keypair, sha256_digest, sha256_bytes
from .model import verify_receipt, receipt_digest
from .replay import ReplayStore

def load(path): return loads(Path(path).read_bytes())
def main(argv=None):
    p=argparse.ArgumentParser(prog='ddcar')
    sp=p.add_subparsers(dest='cmd',required=True)
    sp.add_parser('keygen')
    v=sp.add_parser('verify'); v.add_argument('receipt'); v.add_argument('--trust',required=True); v.add_argument('--parents'); v.add_argument('--replay-db'); v.add_argument('--mode',choices=['historical','preflight'],default='historical'); v.add_argument('--decision-only',action='store_true')
    for name in ('canonicalize','digest'):
        x=sp.add_parser(name); x.add_argument('json_file')
    args=p.parse_args(argv)
    try:
        if args.cmd=='keygen':
            sk,pk=generate_keypair(); print(json.dumps({'private_key':sk,'public_key':pk},indent=2)); return 0
        if args.cmd=='canonicalize': sys.stdout.buffer.write(canonical_bytes(load(args.json_file))+b'\n'); return 0
        if args.cmd=='digest': print(sha256_digest(load(args.json_file))); return 0
        r=load(args.receipt); trust=load(args.trust)
        parents=None
        if args.parents:
            parents={receipt_digest(x):x for x in load(args.parents)}
        errors=verify_receipt(r,trust=trust,previous_receipts=parents,mode=args.mode,require_execution=not args.decision_only)
        if not errors and args.replay_db:
            store=ReplayStore(args.replay_db)
            try:
                if not store.reserve(r['issuer']['id'],r['nonce'],receipt_digest(r)): errors.append('replay detected')
            finally: store.close()
        result={'valid':not errors,'receipt_digest':receipt_digest(r),'decision':r['decision'],'errors':errors,'limitations':['Signature verification does not establish physical outcome or independent time.']}
        print(json.dumps(result,indent=2)); return 0 if not errors else 2
    except Exception as e:
        print(json.dumps({'valid':False,'errors':[str(e)]})); return 2
if __name__=='__main__': sys.exit(main())
