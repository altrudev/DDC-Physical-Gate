"""Tool-contract and execution-route commitments for Physical Gate v0.5 candidate."""
from __future__ import annotations

from .core import digest, sign, verify

TOOL_CONTRACT_VERSION = "ddc.physical-tool-contract.v0.5"
ROUTE_VERSION = "ddc.physical-route.v0.5"


def tool_contract(
    *,
    tool_id,
    version,
    operations,
    parameter_schema,
    transport,
    implementation_digest,
    behavior_profile_digest,
    behavior_observed_ms,
    behavior_valid_until_ms,
):
    return {
        "version": TOOL_CONTRACT_VERSION,
        "tool_id": tool_id,
        "tool_version": version,
        "operations": sorted(set(operations)),
        "parameter_schema": parameter_schema,
        "transport": transport,
        "implementation_digest": implementation_digest,
        "behavior_profile_digest": behavior_profile_digest,
        "behavior_observed_ms": behavior_observed_ms,
        "behavior_valid_until_ms": behavior_valid_until_ms,
    }


def tool_contract_digest(contract):
    if not isinstance(contract, dict) or contract.get("version") != TOOL_CONTRACT_VERSION:
        raise ValueError("invalid-tool-contract")
    return digest(contract)


def verify_tool_contract(contract, now_ms):
    try:
        contract_digest = tool_contract_digest(contract)
    except (TypeError, ValueError):
        return False, "TOOL_CONTRACT_INVALID", None
    if not isinstance(contract.get("implementation_digest"), str) or not contract.get("implementation_digest"):
        return False, "TOOL_IMPLEMENTATION_IDENTITY", None
    if not isinstance(contract.get("behavior_profile_digest"), str) or not contract.get("behavior_profile_digest"):
        return False, "TOOL_BEHAVIOR_PROFILE", None
    try:
        observed = contract.get("behavior_observed_ms")
        valid_until = contract.get("behavior_valid_until_ms")
        if observed > now_ms or valid_until <= now_ms or valid_until <= observed:
            return False, "TOOL_BEHAVIOR_STALE", None
    except TypeError:
        return False, "TOOL_BEHAVIOR_TIME", None
    return True, None, contract_digest


def route_commitment(
    *,
    route_id,
    gate_id,
    executor_id,
    device,
    action_digest,
    tool_contract_digest,
    entrypoint_digest,
    closure_evidence_digest,
    enforcement_digest,
    issued_ms,
    expires_ms,
    exclusive=True,
):
    return {
        "version": ROUTE_VERSION,
        "route_id": route_id,
        "gate_id": gate_id,
        "executor_id": executor_id,
        "device": device,
        "action_digest": action_digest,
        "tool_contract_digest": tool_contract_digest,
        "entrypoint_digest": entrypoint_digest,
        "closure_evidence_digest": closure_evidence_digest,
        "enforcement_digest": enforcement_digest,
        "issued_ms": issued_ms,
        "expires_ms": expires_ms,
        "exclusive": bool(exclusive),
    }


def sign_route(private_key, **kwargs):
    return sign(private_key, route_commitment(**kwargs))


def verify_route(
    signed,
    trusted,
    *,
    envelope,
    now_ms,
    expected_tool_contract_digest,
    expected_gate_id=None,
    expected_executor_id=None,
    expected_entrypoint_digest=None,
    expected_closure_evidence_digest=None,
    expected_enforcement_digest=None,
):
    if not verify(signed, trusted):
        return False, "ROUTE_SIGNATURE"
    route = signed.get("payload", {})
    if route.get("version") != ROUTE_VERSION:
        return False, "ROUTE_VERSION"
    if route.get("exclusive") is not True:
        return False, "ROUTE_NOT_EXCLUSIVE"
    if route.get("device") != envelope.get("device"):
        return False, "ROUTE_DEVICE"
    if route.get("action_digest") != digest(envelope.get("action", {})):
        return False, "ROUTE_ACTION"
    if route.get("tool_contract_digest") != expected_tool_contract_digest:
        return False, "ROUTE_TOOL_CONTRACT"
    if expected_gate_id is not None and route.get("gate_id") != expected_gate_id:
        return False, "ROUTE_GATE"
    if expected_executor_id is not None and route.get("executor_id") != expected_executor_id:
        return False, "ROUTE_EXECUTOR"
    if expected_entrypoint_digest is not None and route.get("entrypoint_digest") != expected_entrypoint_digest:
        return False, "ROUTE_ENTRYPOINT"
    if not isinstance(route.get("closure_evidence_digest"), str) or not route.get("closure_evidence_digest"):
        return False, "ROUTE_CLOSURE_EVIDENCE"
    if not isinstance(route.get("enforcement_digest"), str) or not route.get("enforcement_digest"):
        return False, "ROUTE_ENFORCEMENT_EVIDENCE"
    if expected_closure_evidence_digest is not None and route.get("closure_evidence_digest") != expected_closure_evidence_digest:
        return False, "ROUTE_CLOSURE_EVIDENCE_CHANGED"
    if expected_enforcement_digest is not None and route.get("enforcement_digest") != expected_enforcement_digest:
        return False, "ROUTE_ENFORCEMENT_CHANGED"
    try:
        if route.get("issued_ms") > now_ms or route.get("expires_ms") <= now_ms:
            return False, "ROUTE_TIME"
    except TypeError:
        return False, "ROUTE_TIME"
    return True, None


def route_digest(signed_route):
    return digest(signed_route.get("payload", {}))
