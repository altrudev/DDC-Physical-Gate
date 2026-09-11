import hashlib, os, tempfile
import pytest
from physical_gate.core import Gate, fixture, digest, keys
from physical_gate.runtime import Simulator, Ledger, issue
from physical_gate.trust import sign_authority, sign_state
from physical_gate.secure_runtime import SecureExecutor
from physical_gate.core import PROFILE

NOW=1000000

def setup():
    sim=Simulator(NOW)
    decision_key,decision_pub=keys(); exec_key,exec_pub=keys(); auth_key,auth_pub=keys(); state_key,state_pub=keys()
    auth=sign_authority(auth_key,principal='human:owner',agent=sim.envelope['agent'],device=sim.envelope['device'],
      operations=PROFILE['operations'],action_digest=digest(sim.envelope['action']),issued_ms=NOW-1,
      expires_ms=NOW+1000,nonce=sim.envelope['nonce'],profile_digest=sim.envelope['profile_digest'])
    state=sign_state(state_key,sim.snapshot(),valid_until_ms=NOW+500,source='simulator:arm-01')
    return sim,decision_key,decision_pub,exec_key,exec_pub,auth,auth_pub,state,state_pub

def test_secure_executor_revalidates_both_proofs():
    sim,dk,dp,ek,ep,a,ap,s,sp=setup()
    d=issue(Gate(),sim.envelope,sim.snapshot(),dk,NOW)
    with tempfile.TemporaryDirectory() as tmp:
        ledger=Ledger(os.path.join(tmp,'l.db'))
        ex=SecureExecutor(sim,ledger,{d['key_id']:dp},ek,
          authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp})
        result=ex.dispatch_secure(sim.envelope,d,authority_proof=a,state_proof=s)
        assert result['payload']['status']=='SIMULATED'
        assert result['payload']['generation_after']==result['payload']['generation_before']+1

def test_secure_executor_rejects_tampered_authority():
    sim,dk,dp,ek,ep,a,ap,s,sp=setup()
    d=issue(Gate(),sim.envelope,sim.snapshot(),dk,NOW)
    a['payload']['operations']=[]
    with tempfile.TemporaryDirectory() as tmp:
        ex=SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:dp},ek,
          authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp})
        with pytest.raises(ValueError,match='secure recheck failed'):
            ex.dispatch_secure(sim.envelope,d,authority_proof=a,state_proof=s)

def test_secure_executor_rejects_tampered_state_attestation():
    sim,dk,dp,ek,ep,a,ap,s,sp=setup()
    d=issue(Gate(),sim.envelope,sim.snapshot(),dk,NOW)
    s['payload']['generation']=999
    with tempfile.TemporaryDirectory() as tmp:
        ex=SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:dp},ek,
          authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp})
        with pytest.raises(ValueError,match='secure recheck failed'):
            ex.dispatch_secure(sim.envelope,d,authority_proof=a,state_proof=s)

def test_secure_executor_rejects_missing_proofs():
    sim,dk,dp,ek,ep,a,ap,s,sp=setup()
    d=issue(Gate(),sim.envelope,sim.snapshot(),dk,NOW)
    with tempfile.TemporaryDirectory() as tmp:
        ex=SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:dp},ek,
          authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp})
        with pytest.raises(ValueError,match='secure recheck failed'):
            ex.dispatch_secure(sim.envelope,d,authority_proof={},state_proof={})
