"""v0.2 cryptographic pre-execution wrapper around the deterministic Gate."""
from .core import Gate, digest, sign
from .trust import verify_authority, verify_state

class SecureGate:
    def __init__(self, *, profile=None, authority_trust=None, state_trust=None, authority_revocations=None, state_lineage=None):
        self.gate=Gate(profile)
        self.authority_trust=authority_trust or {}
        self.state_trust=state_trust or {}
        self.authority_revocations=authority_revocations if authority_revocations is not None else set()
        self.state_lineage=state_lineage

    @property
    def profile(self): return self.gate.profile

    def evaluate(self,envelope,snapshot,now_ms,*,authority_proof=None,state_proof=None,simulation=None,history=None):
        base=self.gate.evaluate(envelope,snapshot,now_ms,simulation,history)
        findings=list(base.get('findings',[]))
        def block(code): findings.append({'code':code,'disposition':'BLOCK'})
        ok,code=verify_authority(authority_proof or {},self.authority_trust,envelope=envelope,now_ms=now_ms,revoked_grants=self.authority_revocations)
        if not ok: block(code)
        ok,code=verify_state(state_proof or {},self.state_trust,snapshot=snapshot,now_ms=now_ms)
        if not ok: block(code)
        elif self.state_lineage is not None:
            ok,code=self.state_lineage.check(state_proof)
            if not ok: block(code)
        base['findings']=findings
        if any(f['disposition']=='BLOCK' for f in findings): base['disposition']='BLOCK'
        base['trust_profile']='cryptographic-v0.2'
        return base


def issue_secure(gate,envelope,snapshot,key,now_ms,*,authority_proof,state_proof,simulation=None,history=None):
    """Issue a signed v0.4 decision bound to the exact trust proofs used at evaluation."""
    d=gate.evaluate(envelope,snapshot,now_ms,authority_proof=authority_proof,state_proof=state_proof,
      simulation=simulation,history=history)
    d.update({'envelope_digest':digest(envelope),
      'expires_ms':min(envelope.get('expires_ms',now_ms),now_ms+gate.profile['max_permit_ms']),
      'authority_proof_digest':digest(authority_proof),
      'state_proof_digest':digest(state_proof),
      'trust_profile':'cryptographic-v0.4'})
    return sign(key,d)
