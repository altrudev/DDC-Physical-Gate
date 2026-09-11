"""v0.2 executor that independently revalidates cryptographic trust before simulated dispatch."""
import copy
from .core import digest, sign, verify
from .runtime import Executor
from .secure_gate import SecureGate

class SecureExecutor(Executor):
    def __init__(self, simulator, ledger, decision_trust, signer, *, authority_trust, state_trust, authority_revocations=None, state_lineage=None):
        super().__init__(simulator,ledger,decision_trust,signer)
        self.state_lineage=state_lineage
        self.secure_gate=SecureGate(authority_trust=authority_trust,state_trust=state_trust,
          authority_revocations=authority_revocations,state_lineage=state_lineage)

    def dispatch_secure(self,envelope,decision,*,authority_proof,state_proof,approved_action=None):
        if not verify(decision,self.trusted): raise ValueError('untrusted decision')
        d=decision['payload']; now=self.sim.now
        if d.get('disposition')!='ALLOW': raise ValueError('not allowed')
        if d.get('trust_profile')!='cryptographic-v0.4': raise ValueError('legacy decision lacks proof binding')
        if d.get('authority_proof_digest')!=digest(authority_proof): raise ValueError('authority proof substitution')
        if d.get('state_proof_digest')!=digest(state_proof): raise ValueError('state proof substitution')
        if d.get('envelope_digest')!=digest(envelope): raise ValueError('envelope changed')
        if d.get('expires_ms',0)<=now or d.get('evaluated_ms',now+1)>now: raise ValueError('permit expired')
        if d.get('action_digest')!=digest(approved_action if approved_action is not None else envelope['action']):
            raise ValueError('action changed')
        snapshot=self.sim.snapshot()
        if d.get('snapshot_digest')!=digest(snapshot): raise ValueError('state changed')
        check=self.secure_gate.evaluate(envelope,snapshot,now,authority_proof=authority_proof,state_proof=state_proof)
        if check['disposition']!='ALLOW': raise ValueError('secure recheck failed')
        if check['profile_digest']!=d['profile_digest']: raise ValueError('profile changed')
        if self.state_lineage is not None:
            ok,code=self.state_lineage.accept(state_proof)
            if not ok: raise ValueError('state lineage: '+code)
        if not self.ledger.reserve(envelope['nonce'],d['action_digest']): raise ValueError('replay')
        before=digest(snapshot)
        try:
            outcome=self.sim.execute(copy.deepcopy(envelope['action']))
            self.ledger.finish(envelope['nonce'],'COMPLETED')
        except BaseException:
            self.ledger.finish(envelope['nonce'],'UNKNOWN')
            raise
        return sign(self.signer,{'version':'ddc.physical-execution.v0.4','decision_digest':digest(d),
          'authority_proof_digest':digest(authority_proof),'state_proof_digest':digest(state_proof),
          'action_digest':d['action_digest'],'before_digest':before,'after_digest':digest(outcome),
          'status':'SIMULATED','device':envelope['device'],'nonce':envelope['nonce'],
          'generation_before':snapshot['generation'],'generation_after':outcome['generation'],
          'completed_ms':self.sim.now})
