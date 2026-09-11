import copy, json, sqlite3, time
from .core import Gate, PROFILE, canonical, digest, sign, verify, fixture

class Simulator:
    """Pure state machine; no network, ROS, serial, GPIO or device SDK access."""
    def __init__(self, now=1000000):
        self.now=now
        self.envelope,self.state=fixture(now)
    def snapshot(self): return copy.deepcopy(self.state)
    def execute(self, action):
        op=action['operation']; p=action['parameters']
        if op=='move':
            self.state['sensors']['position']['value']={k:float(v['value']) for k,v in p['target'].items()}
        elif op=='grip': self.state['gripper']='CLOSED'
        elif op=='release': self.state['gripper']='OPEN'
        elif op=='home': self.state['sensors']['position']['value']={'x':0,'y':0,'z':100}; self.state['sensors']['homed']['value']=True
        self.state['generation']+=1
        self.now+=1
        self.state['observed_ms']=self.now
        for s in self.state['sensors'].values(): s['observed_ms']=self.now
        return self.snapshot()

class Ledger:
    def __init__(self,path):
        self.db=sqlite3.connect(path, isolation_level=None)
        self.db.execute('CREATE TABLE IF NOT EXISTS reservations (nonce TEXT PRIMARY KEY, action_digest TEXT NOT NULL, status TEXT NOT NULL)')
    def reserve(self,nonce,action_digest):
        try:
            self.db.execute('INSERT INTO reservations VALUES (?,?,?)',(nonce,action_digest,'RESERVED'))
            return True
        except sqlite3.IntegrityError: return False
    def finish(self,nonce,status): self.db.execute('UPDATE reservations SET status=? WHERE nonce=?',(status,nonce))
    def close(self): self.db.close()

class Executor:
    def __init__(self, simulator, ledger, trusted, signer):
        self.sim=simulator; self.ledger=ledger; self.trusted=trusted; self.signer=signer
    def dispatch(self, envelope, decision, approved_action=None):
        if not verify(decision,self.trusted): raise ValueError('untrusted decision')
        d=decision['payload']; now=self.sim.now
        if d.get('disposition')!='ALLOW': raise ValueError('not allowed')
        if d.get('envelope_digest')!=digest(envelope): raise ValueError('envelope changed')
        if d.get('expires_ms',0)<=now or d.get('evaluated_ms',now+1)>now: raise ValueError('permit expired')
        if d.get('action_digest')!=digest(approved_action if approved_action is not None else envelope['action']): raise ValueError('action changed')
        snapshot=self.sim.snapshot()
        if d.get('snapshot_digest')!=digest(snapshot): raise ValueError('state changed')
        check=Gate().evaluate(envelope,snapshot,now)
        if check['disposition']!='ALLOW' or check['profile_digest']!=d['profile_digest']: raise ValueError('recheck failed')
        if not self.ledger.reserve(envelope['nonce'],d['action_digest']): raise ValueError('replay')
        before=digest(snapshot)
        try:
            outcome=self.sim.execute(copy.deepcopy(envelope['action']))
            self.ledger.finish(envelope['nonce'],'COMPLETED')
            status='SIMULATED'
        except BaseException:
            self.ledger.finish(envelope['nonce'],'UNKNOWN')
            raise
        return sign(self.signer,{'version':'ddc.physical-execution.v0.1','decision_digest':digest(d),'action_digest':d['action_digest'],'before_digest':before,'after_digest':digest(outcome),'status':status,'device':envelope['device'],'nonce':envelope['nonce'],'completed_ms':self.sim.now})

def issue(gate, envelope, snapshot, key, now, simulation=None):
    d=gate.evaluate(envelope,snapshot,now,simulation)
    d.update({'envelope_digest':digest(envelope),'expires_ms':min(envelope.get('expires_ms',now),now+gate.profile['max_permit_ms'])})
    return sign(key,d)

def receipt(envelope,decision,execution):
    """Portable physical profile for DDCAR; not a claim of core DDCAR schema compatibility."""
    return {'profile':'ddcar.physical.v0.1-draft','envelope_digest':digest(envelope),'decision':decision,'execution':execution,'evidence':{'profile_digest':decision['payload']['profile_digest'],'snapshot_digest':decision['payload']['snapshot_digest']},'outcome_claim':'SIMULATED'}
