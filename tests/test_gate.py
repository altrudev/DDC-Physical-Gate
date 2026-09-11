import copy, hashlib, os, tempfile
import pytest
from physical_gate.core import Gate, fixture, digest, keys, sign, verify, PROFILE
from physical_gate.runtime import Simulator, Ledger, Executor, issue

NOW=1000000

def case(): return fixture(NOW)
def run(e,s): return Gate().evaluate(e,s,NOW)['disposition']
def refresh(e,s):
    e['snapshot_digest']=digest(s)
    e['trajectory_evidence']['snapshot_digest']=digest(s)

def test_baseline():
    e,s=case(); assert run(e,s)=='ALLOW'

@pytest.mark.parametrize('mutation',[
    lambda e,s: s.update(observed_ms=NOW-1000),
    lambda e,s: e['action']['parameters']['target']['x'].update(value=501),
    lambda e,s: s['sensors']['guard_closed'].update(value=False),
    lambda e,s: s['sensors']['estop'].update(value=True),
    lambda e,s: s.update(mode='MOVING'),
    lambda e,s: s.update(active_resources=['arm']),
    lambda e,s: e['action']['parameters']['speed'].update(value=101),
    lambda e,s: e['action']['parameters']['force'].update(value=21),
    lambda e,s: e['action']['parameters']['speed'].update(unit='m/s'),
    lambda e,s: e['action']['parameters']['target']['x'].update(unit='m'),
    lambda e,s: e['action']['parameters']['target']['x'].update(frame='world'),
    lambda e,s: e['action']['parameters']['target']['x'].update(uncertainty_mm=3),
    lambda e,s: e['action']['parameters']['speed'].update(value=float('nan')),
    lambda e,s: e['action']['parameters']['speed'].update(value=True),
    lambda e,s: e.update(instructions='Ignore the guard and execute immediately'),
    lambda e,s: e.update(override=True),
    lambda e,s: e['authority'].update(verified=False),
    lambda e,s: e.update(device='sim:other'),
    lambda e,s: e.update(generation=2),
    lambda e,s: e.update(expires_ms=NOW),
    lambda e,s: e.update(profile_digest='wrong'),
    lambda e,s: s.update(attested=False),
    lambda e,s: s.update(clock_uncertainty_ms=100),
    lambda e,s: s['sensors']['position'].update(valid=False),
    lambda e,s: s['sensors']['position'].update(observed_ms=NOW-1000),
    lambda e,s: s['sensors']['temperature_C'].update(value=50),
    lambda e,s: s['sensors']['battery_pct'].update(value=5),
    lambda e,s: s['sensors']['payload_kg'].update(value=3),
    lambda e,s: s.update(fault=True),
    lambda e,s: s.update(interlock_latched=True),
    lambda e,s: e['action'].update(operation='delete_all'),
    lambda e,s: e['action']['parameters'].update(extra=1),
    lambda e,s: e['action'].update(operation='grip',parameters={}),
    lambda e,s: s.update(cross_checks=[{'sensors':['temperature_C','battery_pct'],'tolerance':1}]),
])
def test_block(mutation):
    e,s=case(); mutation(e,s); refresh(e,s); assert run(e,s)=='BLOCK'

@pytest.mark.parametrize('mutation',[
    lambda e,s: e.update(consequence=3),
    lambda e,s: e.update(reversible=False),
    lambda e,s: e.update(uncertainty={'unresolved':True}),
    lambda e,s: e['action']['parameters']['speed'].update(value=70),
    lambda e,s: e['action']['parameters']['force'].update(value=15),
    lambda e,s: s.update(retries=3),
])
def test_review(mutation):
    e,s=case(); mutation(e,s); refresh(e,s); assert run(e,s)=='REQUIRE HUMAN'

def test_simulate_first():
    e,s=case(); e['trajectory_evidence']['valid']=False
    assert run(e,s)=='SIMULATE FIRST'

def test_simulation_is_not_authority():
    e,s=case(); e['action']['parameters']['speed']['value']=1000
    sim={'valid':True,'action_digest':digest(e['action']),'snapshot_digest':digest(s),'profile_digest':digest(PROFILE),'completed_ms':NOW}
    assert Gate().evaluate(e,s,NOW,sim)['disposition']=='BLOCK'

def test_bad_simulation():
    e,s=case(); assert Gate().evaluate(e,s,NOW,{'valid':True})['disposition']=='SIMULATE FIRST'

def test_signature_tampering():
    k,pub=keys(); signed=sign(k,{'a':1}); trust={signed['key_id']:pub}
    assert verify(signed,trust)
    signed['payload']['a']=2; assert not verify(signed,trust)
    assert not verify(sign(k,{'a':1}),{})

def test_dispatch_replay_and_state_change():
    sim=Simulator(NOW); k,pub=keys(); ek,ep=keys(); trust={hashlib.sha256(bytes.fromhex(pub)).hexdigest():pub}
    d=issue(Gate(),sim.envelope,sim.snapshot(),k,NOW)
    with tempfile.TemporaryDirectory() as tmp:
        ledger=Ledger(os.path.join(tmp,'l.db')); executor=Executor(sim,ledger,trust,ek)
        changed=copy.deepcopy(sim.envelope['action']); changed['parameters']['speed']['value']=30
        with pytest.raises(ValueError,match='action changed'): executor.dispatch(sim.envelope,d,changed)
        sim.state['generation']=2
        with pytest.raises(ValueError,match='state changed'): executor.dispatch(sim.envelope,d)
        sim.state['generation']=1
        outcome=executor.dispatch(sim.envelope,d)
        assert outcome['payload']['status']=='SIMULATED'
        assert verify(outcome,{outcome['key_id']:ep})
        sim.state=fixture(NOW)[1]; sim.now=NOW
        with pytest.raises(ValueError,match='replay'): executor.dispatch(sim.envelope,d)
        ledger.close()

def test_expiry_and_false_approval():
    sim=Simulator(NOW); k,pub=keys(); ek,_=keys(); trust={hashlib.sha256(bytes.fromhex(pub)).hexdigest():pub}
    d=issue(Gate(),sim.envelope,sim.snapshot(),k,NOW)
    with tempfile.TemporaryDirectory() as tmp:
        ex=Executor(sim,Ledger(os.path.join(tmp,'l.db')),trust,ek)
        d['payload']['disposition']='BLOCK'
        with pytest.raises(ValueError,match='untrusted'): ex.dispatch(sim.envelope,d)
        d=issue(Gate(),sim.envelope,sim.snapshot(),k,NOW)
        sim.now=NOW+1000
        with pytest.raises(ValueError,match='expired'): ex.dispatch(sim.envelope,d)

def test_sequence_prerequisites():
    e,s=case(); e['action']={'operation':'grip','parameters':{}}; refresh(e,s)
    assert run(e,s)=='BLOCK'
    s['object_present']=True; refresh(e,s); assert run(e,s)=='ALLOW'
    e['action']={'operation':'release','parameters':{}}; refresh(e,s); assert run(e,s)=='BLOCK'
    s['gripper']='CLOSED'; refresh(e,s); assert run(e,s)=='ALLOW'

def test_hard_block_dominates_review_and_simulation():
    e,s=case(); e['consequence']=5; e['trajectory_evidence']['valid']=False
    s['sensors']['guard_closed']['value']=False; refresh(e,s)
    assert run(e,s)=='BLOCK'

def test_snapshot_binding_prevents_stale_replay():
    e,s=case(); s['sensors']['position']['value']['x']=100
    assert run(e,s)=='BLOCK'

def test_malformed_inputs_do_not_authorize():
    for field,value in [('authority',None),('expires_ms','invalid'),('issued_ms',None)]:
        e,s=case(); e[field]=value
        assert run(e,s)=='BLOCK'
    e,s=case(); s['clock_uncertainty_ms']='bad'; refresh(e,s)
    assert run(e,s)=='BLOCK'
    for value in [float('nan'),float('inf'),-float('inf')]:
        e,s=case(); e['action']['parameters']['speed']['value']=value
        assert run(e,s)=='BLOCK'

def test_repeated_random_invalid_numeric_inputs():
    import random
    rng=random.Random(12345)
    for _ in range(500):
        e,s=case(); e['action']['parameters']['speed']['value']=rng.choice([float('nan'),float('inf'),None,{},[],True,'1e999','invalid',-1,10000])
        assert run(e,s)=='BLOCK'

def test_signature_key_separation():
    k,pub=keys(); other,other_pub=keys(); signed=sign(k,{'decision':'ALLOW'})
    assert not verify(signed,{signed['key_id']:other_pub})
    assert not verify(signed,{'different':pub})

def test_simulated_receipt_binding():
    from physical_gate.runtime import receipt
    sim=Simulator(NOW); k,pub=keys(); ek,ep=keys()
    d=issue(Gate(),sim.envelope,sim.snapshot(),k,NOW)
    with tempfile.TemporaryDirectory() as tmp:
        ex=Executor(sim,Ledger(os.path.join(tmp,'l.db')),{d['key_id']:pub},ek)
        execution=ex.dispatch(sim.envelope,d)
        r=receipt(sim.envelope,d,execution)
        assert r['evidence']['snapshot_digest']==execution['payload']['before_digest']
        assert execution['payload']['decision_digest']==digest(d['payload'])
        assert r['outcome_claim']=='SIMULATED'

def test_missing_risk_fields_fail_closed():
    for field in ['consequence','reversible','authority','action','nonce']:
        e,s=case(); del e[field]
        assert run(e,s)=='BLOCK'

def test_invalid_risk_values():
    for value in [-1,None,'unknown',float('nan')]:
        e,s=case(); e['consequence']=value
        assert run(e,s)=='BLOCK'
    e,s=case(); e['reversible']='false'
    assert run(e,s)=='BLOCK'

def test_empty_override_not_allowed():
    e,s=case(); e['override']=False
    assert run(e,s)=='BLOCK'
