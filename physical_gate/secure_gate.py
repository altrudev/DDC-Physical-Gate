"""v0.2 cryptographic pre-execution wrapper around the deterministic Gate."""
from .core import Gate
from .trust import verify_authority, verify_state

class SecureGate:
    def __init__(self, *, profile=None, authority_trust=None, state_trust=None):
        self.gate=Gate(profile)
        self.authority_trust=authority_trust or {}
        self.state_trust=state_trust or {}

    @property
    def profile(self): return self.gate.profile

    def evaluate(self,envelope,snapshot,now_ms,*,authority_proof=None,state_proof=None,simulation=None,history=None):
        base=self.gate.evaluate(envelope,snapshot,now_ms,simulation,history)
        findings=list(base.get('findings',[]))
        def block(code): findings.append({'code':code,'disposition':'BLOCK'})
        ok,code=verify_authority(authority_proof or {},self.authority_trust,envelope=envelope,now_ms=now_ms)
        if not ok: block(code)
        ok,code=verify_state(state_proof or {},self.state_trust,snapshot=snapshot,now_ms=now_ms)
        if not ok: block(code)
        base['findings']=findings
        if any(f['disposition']=='BLOCK' for f in findings): base['disposition']='BLOCK'
        base['trust_profile']='cryptographic-v0.2'
        return base
