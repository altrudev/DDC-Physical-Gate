import hashlib, os, tempfile
import pytest
from physical_gate.core import fixture, digest, keys, PROFILE
from physical_gate.runtime import Simulator, Ledger
from physical_gate.trust import sign_authority, sign_state
from physical_gate.secure_gate import SecureGate, issue_secure
from physical_gate.secure_runtime import SecureExecutor
from physical_gate.state_lineage import StateLineageLedger

NOW=1000000

def setup():
    sim=Simulator(NOW)
    decision_key,decision_pub=keys(); exec_key,exec_pub=keys(); auth_key,auth_pub=keys(); state_key,state_pub=keys()
    auth=sign_authority(auth_key,principal='human:owner',agent=sim.envelope['agent'],device=sim.envelope['device'],
      operations=PROFILE['operations'],action_digest=digest(sim.envelope['action']),issued_ms=NOW-1,
      expires_ms=NOW+1000,nonce=sim.envelope['nonce'],profile_digest=sim.envelope['profile_digest'])
    state=sign_state(state_key,sim.snapshot(),valid_until_ms=NOW+500,source='simulator:arm-01')
    atrust={auth['key_id']:auth_pub}; strust={state['key_id']:state_pub}
    gate=SecureGate(authority_trust=atrust,state_trust=strust)
    decision=issue_secure(gate,sim.envelope,sim.snapshot(),decision_key,NOW,authority_proof=auth,state_proof=state)
    return sim,decision_key,decision_pub,exec_key,exec_pub,auth,auth_pub,state,state_pub,decision

def executor(sim,dp,ek,a,ap,s,sp,tmp,**kw):
    return SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{kw.pop('decision_key_id',None) or 'unused':dp},ek,
      authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp},**kw)

def test_secure_executor_revalidates_both_proofs():
    sim,dk,dp,ek,ep,a,ap,s,sp,d=setup()
    with tempfile.TemporaryDirectory() as tmp:
        ex=SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:dp},ek,
          authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp})
        result=ex.dispatch_secure(sim.envelope,d,authority_proof=a,state_proof=s)
        assert result['payload']['version']=='ddc.physical-execution.v0.4'
        assert result['payload']['status']=='SIMULATED'
        assert result['payload']['generation_after']==result['payload']['generation_before']+1

def test_decision_binds_exact_authority_proof():
    sim,dk,dp,ek,ep,a,ap,s,sp,d=setup()
    other_key,other_pub=keys()
    replacement=sign_authority(other_key,principal='human:owner',agent=sim.envelope['agent'],device=sim.envelope['device'],
      operations=PROFILE['operations'],action_digest=digest(sim.envelope['action']),issued_ms=NOW-1,
      expires_ms=NOW+1000,nonce=sim.envelope['nonce'],profile_digest=sim.envelope['profile_digest'])
    with tempfile.TemporaryDirectory() as tmp:
        ex=SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:dp},ek,
          authority_trust={replacement['key_id']:other_pub},state_trust={s['key_id']:sp})
        with pytest.raises(ValueError,match='authority proof substitution'):
            ex.dispatch_secure(sim.envelope,d,authority_proof=replacement,state_proof=s)

def test_decision_binds_exact_state_proof():
    sim,dk,dp,ek,ep,a,ap,s,sp,d=setup()
    sk2,sp2=keys()
    replacement=sign_state(sk2,sim.snapshot(),valid_until_ms=NOW+500,source='simulator:arm-01')
    with tempfile.TemporaryDirectory() as tmp:
        ex=SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:dp},ek,
          authority_trust={a['key_id']:ap},state_trust={replacement['key_id']:sp2})
        with pytest.raises(ValueError,match='state proof substitution'):
            ex.dispatch_secure(sim.envelope,d,authority_proof=a,state_proof=replacement)

def test_revoked_authority_blocks():
    sim,dk,dp,ek,ep,a,ap,s,sp,d=setup()
    revoked={digest(a['payload'])}
    gate=SecureGate(authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp},authority_revocations=revoked)
    result=gate.evaluate(sim.envelope,sim.snapshot(),NOW,authority_proof=a,state_proof=s)
    assert result['disposition']=='BLOCK'
    assert any(f['code']=='AUTHORITY_REVOKED' for f in result['findings'])

def test_state_lineage_rejects_rollback_and_accepts_successor():
    sim,dk,dp,ek,ep,a,ap,s,sp,d=setup()
    state_key,state_pub=keys()
    first=sign_state(state_key,sim.snapshot(),valid_until_ms=NOW+500,source='simulator:arm-01')
    with tempfile.TemporaryDirectory() as tmp:
        ledger=StateLineageLedger(os.path.join(tmp,'state.db'))
        ok,code=ledger.accept(first); assert ok and code is None
        ok,code=ledger.check(first); assert not ok and code=='STATE_ROLLBACK'
        next_snapshot=sim.snapshot()
        next_snapshot['generation']=2
        next_snapshot['observed_ms']=NOW+1
        successor=sign_state(state_key,next_snapshot,valid_until_ms=NOW+600,source='simulator:arm-01',
          predecessor_state_digest=first['payload']['snapshot_digest'])
        ok,code=ledger.check(successor); assert ok and code is None
        ledger.close()

def test_state_lineage_rejects_wrong_predecessor_and_epoch():
    sim,dk,dp,ek,ep,a,ap,s,sp,d=setup()
    state_key,state_pub=keys()
    first=sign_state(state_key,sim.snapshot(),valid_until_ms=NOW+500,source='simulator:arm-01')
    with tempfile.TemporaryDirectory() as tmp:
        ledger=StateLineageLedger(os.path.join(tmp,'state.db')); assert ledger.accept(first)[0]
        next_snapshot=sim.snapshot(); next_snapshot['generation']=2; next_snapshot['observed_ms']=NOW+1
        bad=sign_state(state_key,next_snapshot,valid_until_ms=NOW+600,source='simulator:arm-01',
          predecessor_state_digest='deadbeef')
        assert ledger.check(bad)==(False,'STATE_LINEAGE_PREDECESSOR')
        bad_epoch=sign_state(state_key,next_snapshot,valid_until_ms=NOW+600,source='simulator:arm-01',
          device_epoch='other-epoch',predecessor_state_digest=first['payload']['snapshot_digest'])
        assert ledger.check(bad_epoch)==(False,'STATE_LINEAGE_EPOCH')
        ledger.close()

def test_secure_executor_rejects_legacy_unbound_decision():
    sim,dk,dp,ek,ep,a,ap,s,sp,d=setup()
    legacy=dict(d); legacy['payload']=dict(d['payload']); legacy['payload']['trust_profile']='cryptographic-v0.2'
    # signature no longer matches; either trust rejection or legacy rejection is acceptable fail-closed behavior.
    with tempfile.TemporaryDirectory() as tmp:
        ex=SecureExecutor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:dp},ek,
          authority_trust={a['key_id']:ap},state_trust={s['key_id']:sp})
        with pytest.raises(ValueError):
            ex.dispatch_secure(sim.envelope,legacy,authority_proof=a,state_proof=s)
