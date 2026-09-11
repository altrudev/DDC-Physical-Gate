import hashlib
import os
import tempfile

import pytest

ddcar=pytest.importorskip("ddcar")
from ddcar.crypto import generate_keypair, sha256_digest
from ddcar.model import verify_receipt

from physical_gate.core import PROFILE, Gate, digest, keys
from physical_gate.runtime import Simulator, Ledger
from physical_gate.secure_gate import SecureGate
from physical_gate.secure_runtime import SecureExecutor
from physical_gate.trust import sign_authority, sign_state
from physical_gate.ddcar import (
    action, canonical_authority_scope, physical_scope,
    build_decision_receipt, bind_simulated_execution,
)


NOW=1_000_000


def setup_stack():
    sim=Simulator(NOW)
    decision_key,decision_pub=keys()
    execution_key,execution_pub=keys()
    physical_authority_key,physical_authority_pub=keys()
    state_key,state_pub=keys()

    authority=sign_authority(
        physical_authority_key,
        principal="human:owner",
        agent=sim.envelope["agent"],
        device=sim.envelope["device"],
        operations=PROFILE["operations"],
        action_digest=digest(sim.envelope["action"]),
        issued_ms=NOW-10,
        expires_ms=NOW+1000,
        nonce=sim.envelope["nonce"],
        profile_digest=sim.envelope["profile_digest"],
    )
    state=sign_state(state_key,sim.snapshot(),valid_until_ms=NOW+500,source="simulator:arm-01")
    authority_trust={authority["key_id"]:physical_authority_pub}
    state_trust={state["key_id"]:state_pub}
    gate=SecureGate(authority_trust=authority_trust,state_trust=state_trust)
    decision=gate.evaluate(sim.envelope,sim.snapshot(),NOW,authority_proof=authority,state_proof=state)
    assert decision["disposition"]=="ALLOW"

    dkeys={role:generate_keypair() for role in ("authority","decision","execution")}
    trust={role:{role+"-key":pair[1]} for role,pair in dkeys.items()}
    trust["bindings"]={
        "authority":{"authority-key":"human:owner"},
        "decision":{"decision-key":"ddc-physical-gate"},
        "execution":{"execution-key":"physical-gate-simulator"},
    }
    return {
        "sim":sim,
        "decision_key":decision_key,
        "decision_pub":decision_pub,
        "execution_key":execution_key,
        "execution_pub":execution_pub,
        "authority":authority,
        "authority_trust":authority_trust,
        "state":state,
        "state_trust":state_trust,
        "decision":decision,
        "dkeys":dkeys,
        "trust":trust,
    }


def test_canonical_scope_is_reference_verifier_compatible_and_exact_action_is_bound():
    x=setup_stack()
    env=x["sim"].envelope
    scope=canonical_authority_scope(env)
    assert scope=={"tool_id":env["device"],"operation":env["action"]["operation"]}
    rich=physical_scope(env,PROFILE)
    assert "workspace" in rich and "max_speed" in rich and "max_force" in rich
    receipt=build_decision_receipt(
        envelope=env,snapshot=x["sim"].snapshot(),decision=x["decision"],
        physical_authority_signed=x["authority"],state_signed=x["state"],
        physical_authority_trust=x["authority_trust"],state_trust=x["state_trust"],
        ddcar_trust=x["trust"],ddcar_authority_private=x["dkeys"]["authority"][0],
        authority_key_id="authority-key",ddcar_decision_private=x["dkeys"]["decision"][0],
        decision_key_id="decision-key",profile=PROFILE,
    )
    assert receipt["authority"]["scope"]==scope
    assert receipt["authority_grant"]["action_digest"]==sha256_digest(action(env))
    assert verify_receipt(receipt,trust=x["trust"],mode="preflight",require_execution=False,
                          now=__import__("datetime").datetime.fromtimestamp(NOW/1000,__import__("datetime").timezone.utc))==[]


def test_simulated_execution_binds_as_canonical_ddcar_without_claiming_real_hardware():
    x=setup_stack()
    env=x["sim"].envelope
    receipt=build_decision_receipt(
        envelope=env,snapshot=x["sim"].snapshot(),decision=x["decision"],
        physical_authority_signed=x["authority"],state_signed=x["state"],
        physical_authority_trust=x["authority_trust"],state_trust=x["state_trust"],
        ddcar_trust=x["trust"],ddcar_authority_private=x["dkeys"]["authority"][0],
        authority_key_id="authority-key",ddcar_decision_private=x["dkeys"]["decision"][0],
        decision_key_id="decision-key",profile=PROFILE,
    )
    with tempfile.TemporaryDirectory() as tmp:
        executor=SecureExecutor(
            x["sim"],Ledger(os.path.join(tmp,"ledger.db")),
            {hashlib.sha256(bytes.fromhex(x["decision_pub"])).hexdigest():x["decision_pub"]},
            x["execution_key"],
            authority_trust=x["authority_trust"],state_trust=x["state_trust"],
        )
        # SecureExecutor expects a signed Physical Gate decision.
        from physical_gate.runtime import issue
        signed_decision=issue(Gate(),env,x["sim"].snapshot(),x["decision_key"],NOW)
        physical_execution=executor.dispatch_secure(
            env,signed_decision,authority_proof=x["authority"],state_proof=x["state"]
        )
        final=bind_simulated_execution(
            receipt,envelope=env,physical_execution_signed=physical_execution,
            physical_execution_trust={physical_execution["key_id"]:x["execution_pub"]},
            ddcar_trust=x["trust"],ddcar_execution_private=x["dkeys"]["execution"][0],
            execution_key_id="execution-key",
        )
    assert final["execution"]["outcome"]["status"]=="SUCCEEDED"
    assert final["execution"]["outcome"]["reference"]=="simulation-only:physical-gate"
    assert final["execution"]["executor"]["kind"]=="simulator"
    assert verify_receipt(
        final,trust=x["trust"],mode="historical",
        now=__import__("datetime").datetime.fromtimestamp((NOW+1)/1000,__import__("datetime").timezone.utc)
    )==[]


def test_untrusted_physical_execution_is_rejected_before_ddcar_binding():
    x=setup_stack()
    env=x["sim"].envelope
    receipt=build_decision_receipt(
        envelope=env,snapshot=x["sim"].snapshot(),decision=x["decision"],
        physical_authority_signed=x["authority"],state_signed=x["state"],
        physical_authority_trust=x["authority_trust"],state_trust=x["state_trust"],
        ddcar_trust=x["trust"],ddcar_authority_private=x["dkeys"]["authority"][0],
        authority_key_id="authority-key",ddcar_decision_private=x["dkeys"]["decision"][0],
        decision_key_id="decision-key",profile=PROFILE,
    )
    fake={"payload":{"status":"SIMULATED","device":env["device"],"nonce":env["nonce"],
                     "action_digest":digest(env["action"]),"completed_ms":NOW+1},
          "signature":"00","algorithm":"Ed25519","key_id":"fake"}
    with pytest.raises(ValueError,match="untrusted physical execution claim"):
        bind_simulated_execution(
            receipt,envelope=env,physical_execution_signed=fake,
            physical_execution_trust={},ddcar_trust=x["trust"],
            ddcar_execution_private=x["dkeys"]["execution"][0],execution_key_id="execution-key",
        )


def test_tampered_physical_authority_is_rejected_before_ddcar_sealing():
    x=setup_stack()
    bad=dict(x["authority"])
    bad["payload"]=dict(bad["payload"],operations=[])
    with pytest.raises(ValueError,match="physical authority verification failed"):
        build_decision_receipt(
            envelope=x["sim"].envelope,snapshot=x["sim"].snapshot(),decision=x["decision"],
            physical_authority_signed=bad,state_signed=x["state"],
            physical_authority_trust=x["authority_trust"],state_trust=x["state_trust"],
            ddcar_trust=x["trust"],ddcar_authority_private=x["dkeys"]["authority"][0],
            authority_key_id="authority-key",ddcar_decision_private=x["dkeys"]["decision"][0],
            decision_key_id="decision-key",profile=PROFILE,
        )
