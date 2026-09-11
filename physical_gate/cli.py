import argparse, json, os, tempfile
from .core import Gate, fixture, keys, digest, verify
from .runtime import Simulator, Ledger, Executor, issue, receipt

def main():
    ap=argparse.ArgumentParser(description='Simulation-only physical assurance')
    ap.add_argument('command',choices=['demo','evaluate','verify'])
    ap.add_argument('--input'); ap.add_argument('--trust'); ap.add_argument('--output')
    args=ap.parse_args()
    if args.command=='verify':
        if not args.input or not args.trust: ap.error('verify requires --input and --trust')
        with open(args.input) as f: signed=json.load(f)
        with open(args.trust) as f: trust=json.load(f)
        ok=verify(signed,trust); print(json.dumps({'signature_valid':ok})); return 0 if ok else 1
    if args.command=='evaluate':
        if not args.input: ap.error('evaluate requires --input')
        with open(args.input) as f: data=json.load(f)
        result=Gate().evaluate(data['envelope'],data['snapshot'],data['now_ms'])
        print(json.dumps(result,indent=2)); return 0
    sim=Simulator(); key,pub=keys(); executor_key,executor_pub=keys()
    trust={__import__('hashlib').sha256(bytes.fromhex(pub)).hexdigest():pub}
    decision=issue(Gate(),sim.envelope,sim.snapshot(),key,sim.now)
    with tempfile.TemporaryDirectory() as d:
        ledger=Ledger(os.path.join(d,'ledger.sqlite'))
        execution=Executor(sim,ledger,trust,executor_key).dispatch(sim.envelope,decision)
        result=receipt(sim.envelope,decision,execution)
        result['verification']={'decision':verify(decision,trust),'execution':verify(execution,{execution['key_id']:executor_pub})}
    text=json.dumps(result,indent=2)
    if args.output:
        with open(args.output,'w') as f: f.write(text+'\n')
    else: print(text)
    return 0
if __name__=='__main__': raise SystemExit(main())
