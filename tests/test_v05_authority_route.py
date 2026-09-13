import uuid

from physical_gate.authority_continuity import (
    sign_delegation,
    sign_root_authority,
    verify_delegation_chain,
)
from physical_gate.contracts_v05 import (
    route_digest,
    sign_route,
    tool_contract,
    tool_contract_digest,
    verify_route,
)
from physical_gate.core import PROFILE, digest, fixture, keys
from physical_gate.trust import key_id_from_public_hex


NOW = 1_000_000


def _identity():
    private, public_hex = keys()
    key_id = key_id_from_public_hex(public_hex)
    return private, key_id, {key_id: public_hex}


def _merge(*stores):
    merged = {}
    for store in stores:
        merged.update(store)
    return merged


def _contract():
    return tool_contract(
        tool_id="sim:arm-01",
        version="sim-v1",
        operations=PROFILE["operations"],
        parameter_schema={"move": ["target", "speed", "force"]},
        transport="simulated",
        implementation_digest="sha256:" + "1" * 64,
        behavior_profile_digest="sha256:" + "5" * 64,
        behavior_observed_ms=NOW - 100,
        behavior_valid_until_ms=NOW + 500,
    )


def _route(route_key, route_trust, envelope, contract_digest):
    return sign_route(
        route_key,
        route_id="route-1",
        gate_id="physical-gate",
        executor_id="physical-executor",
        device=envelope["device"],
        action_digest=digest(envelope["action"]),
        tool_contract_digest=contract_digest,
        entrypoint_digest="sha256:" + "2" * 64,
        closure_evidence_digest="sha256:" + "3" * 64,
        enforcement_digest="sha256:" + "4" * 64,
        issued_ms=NOW - 10,
        expires_ms=NOW + 500,
        exclusive=True,
    )


def test_monotonic_delegation_binds_principal_tool_route_and_budget():
    envelope, _ = fixture(NOW)
    root_key, root_kid, root_trust = _identity()
    child_key, child_kid, child_trust = _identity()
    route_key, _, route_trust = _identity()
    trusted = _merge(root_trust, child_trust)
    contract = _contract()
    contract_digest = tool_contract_digest(contract)
    route = _route(route_key, route_trust, envelope, contract_digest)
    route_binding = route_digest(route)

    root = sign_root_authority(
        root_key,
        principal="human:owner",
        agent="agent:planner",
        device=envelope["device"],
        operations=["move", "home"],
        issued_ms=NOW - 100,
        expires_ms=NOW + 800,
        nonce=str(uuid.uuid4()),
        profile_digest=envelope["profile_digest"],
        action_digest=digest(envelope["action"]),
        budgets={"force_N": 10, "speed_mm_s": 40},
    )
    child = sign_delegation(
        child_key,
        parent_digest=digest(root["payload"]),
        principal="agent:planner",
        delegate=envelope["agent"],
        device=envelope["device"],
        operations=["move"],
        issued_ms=NOW - 50,
        expires_ms=NOW + 400,
        nonce=str(uuid.uuid4()),
        profile_digest=envelope["profile_digest"],
        action_digest=digest(envelope["action"]),
        tool_contract_digest=contract_digest,
        route_digest=route_binding,
        budgets={"force_N": 5, "speed_mm_s": 20},
    )

    ok, code, info = verify_delegation_chain(
        [child],
        trusted,
        root_authority=root["payload"],
        envelope=envelope,
        now_ms=NOW,
        expected_tool_contract_digest=contract_digest,
        expected_route_digest=route_binding,
        principal_keys={
            "human:owner": [root_kid],
            "agent:planner": [child_kid],
        },
    )
    assert ok
    assert code is None
    assert info["depth"] == 1


def test_delegation_cannot_expand_operations_or_budget():
    envelope, _ = fixture(NOW)
    root_key, root_kid, root_trust = _identity()
    child_key, child_kid, child_trust = _identity()
    root = sign_root_authority(
        root_key,
        principal="human:owner",
        agent="agent:planner",
        device=envelope["device"],
        operations=["move"],
        issued_ms=NOW - 100,
        expires_ms=NOW + 800,
        nonce=str(uuid.uuid4()),
        profile_digest=envelope["profile_digest"],
        budgets={"force_N": 5},
    )
    child = sign_delegation(
        child_key,
        parent_digest=digest(root["payload"]),
        principal="agent:planner",
        delegate=envelope["agent"],
        device=envelope["device"],
        operations=["move", "home"],
        issued_ms=NOW - 50,
        expires_ms=NOW + 400,
        nonce=str(uuid.uuid4()),
        profile_digest=envelope["profile_digest"],
        budgets={"force_N": 6},
    )
    ok, code, _ = verify_delegation_chain(
        [child],
        _merge(root_trust, child_trust),
        root_authority=root["payload"],
        envelope=envelope,
        now_ms=NOW,
        principal_keys={
            "human:owner": [root_kid],
            "agent:planner": [child_kid],
        },
    )
    assert not ok
    assert code.startswith("DELEGATION_OPERATIONS") or code.startswith("DELEGATION_BUDGET")


def test_trusted_key_cannot_impersonate_another_delegating_principal():
    envelope, _ = fixture(NOW)
    root_key, root_kid, root_trust = _identity()
    wrong_key, wrong_kid, wrong_trust = _identity()
    root = sign_root_authority(
        root_key,
        principal="human:owner",
        agent="agent:planner",
        device=envelope["device"],
        operations=["move"],
        issued_ms=NOW - 100,
        expires_ms=NOW + 800,
        nonce=str(uuid.uuid4()),
        profile_digest=envelope["profile_digest"],
    )
    forged = sign_delegation(
        wrong_key,
        parent_digest=digest(root["payload"]),
        principal="agent:planner",
        delegate=envelope["agent"],
        device=envelope["device"],
        operations=["move"],
        issued_ms=NOW - 50,
        expires_ms=NOW + 400,
        nonce=str(uuid.uuid4()),
        profile_digest=envelope["profile_digest"],
    )
    ok, code, _ = verify_delegation_chain(
        [forged],
        _merge(root_trust, wrong_trust),
        root_authority=root["payload"],
        envelope=envelope,
        now_ms=NOW,
        principal_keys={
            "human:owner": [root_kid],
            "agent:planner": ["not-" + wrong_kid],
        },
    )
    assert not ok
    assert code.startswith("DELEGATION_SIGNER_PRINCIPAL")


def test_route_binding_rejects_tool_contract_drift():
    envelope, _ = fixture(NOW)
    route_key, _, route_trust = _identity()
    contract = _contract()
    route = _route(route_key, route_trust, envelope, tool_contract_digest(contract))
    drifted = dict(contract)
    drifted["implementation_digest"] = "sha256:" + "9" * 64

    ok, code = verify_route(
        route,
        route_trust,
        envelope=envelope,
        now_ms=NOW,
        expected_tool_contract_digest=tool_contract_digest(drifted),
        expected_gate_id="physical-gate",
        expected_executor_id="physical-executor",
        expected_entrypoint_digest="sha256:" + "2" * 64,
        expected_closure_evidence_digest="sha256:" + "3" * 64,
        expected_enforcement_digest="sha256:" + "4" * 64,
    )
    assert not ok
    assert code == "ROUTE_TOOL_CONTRACT"


def test_tool_contract_behavior_profile_expires():
    contract = _contract()
    contract["behavior_valid_until_ms"] = NOW
    from physical_gate.contracts_v05 import tool_contract_digest

    try:
        tool_contract_digest(contract, NOW)
    except ValueError as exc:
        assert "tool-behavior-stale" in str(exc)
        return
    raise AssertionError("expected stale behavior profile to fail closed")
