"""Authority continuity and monotonic delegation checks for Physical Gate v0.5 candidate.

This module is additive. Existing v0.4 trust objects remain supported by the
existing gate; v0.5 callers can supply a signed delegation chain when authority
passes through multiple actors before execution.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Iterable

from .core import digest, sign, verify

DELEGATION_VERSION = "ddc.physical-delegation.v0.5"


def _num(value):
    if isinstance(value, bool):
        raise ValueError("boolean-is-not-number")
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("invalid-number")
    if not number.is_finite():
        raise ValueError("nonfinite-number")
    return number


def delegation_grant(
    *,
    parent_digest,
    principal,
    delegate,
    device,
    operations,
    issued_ms,
    expires_ms,
    nonce,
    profile_digest,
    action_digest=None,
    tool_contract_digest=None,
    route_digest=None,
    budgets=None,
):
    """Build one attenuating delegation edge."""
    payload = {
        "version": DELEGATION_VERSION,
        "parent_digest": parent_digest,
        "principal": principal,
        "delegate": delegate,
        "device": device,
        "operations": sorted(set(operations)),
        "issued_ms": issued_ms,
        "expires_ms": expires_ms,
        "nonce": nonce,
        "profile_digest": profile_digest,
        "budgets": dict(budgets or {}),
    }
    if action_digest is not None:
        payload["action_digest"] = action_digest
    if tool_contract_digest is not None:
        payload["tool_contract_digest"] = tool_contract_digest
    if route_digest is not None:
        payload["route_digest"] = route_digest
    return payload


def sign_delegation(private_key, **kwargs):
    return sign(private_key, delegation_grant(**kwargs))


def _subset(child, parent):
    return set(child or []).issubset(set(parent or []))


def _budgets_attenuate(child, parent):
    child = child or {}
    parent = parent or {}
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return False
    for key, value in child.items():
        if key not in parent:
            return False
        try:
            if _num(value) < 0 or _num(value) > _num(parent[key]):
                return False
        except ValueError:
            return False
    return True


def _bound_or_narrower(child, parent, field):
    parent_value = parent.get(field)
    child_value = child.get(field)
    return parent_value is None or child_value == parent_value


def verify_delegation_chain(
    chain: Iterable[dict],
    trusted,
    *,
    root_authority,
    envelope,
    now_ms,
    revoked=None,
    expected_tool_contract_digest=None,
    expected_route_digest=None,
):
    """Verify signatures, linkage, freshness and monotonic attenuation."""
    revoked = revoked if revoked is not None else set()
    parent = dict(root_authority or {})
    parent_digest = digest(parent)
    edges = list(chain or [])

    for index, signed in enumerate(edges):
        if not verify(signed, trusted):
            return False, f"DELEGATION_SIGNATURE:{index}", None
        child = signed.get("payload", {})
        if child.get("version") != DELEGATION_VERSION:
            return False, f"DELEGATION_VERSION:{index}", None
        if digest(child) in revoked:
            return False, f"DELEGATION_REVOKED:{index}", None
        if child.get("parent_digest") != parent_digest:
            return False, f"DELEGATION_PARENT:{index}", None
        if child.get("principal") != parent.get("agent", parent.get("delegate")):
            return False, f"DELEGATION_PRINCIPAL:{index}", None
        if child.get("device") != parent.get("device"):
            return False, f"DELEGATION_DEVICE:{index}", None
        if child.get("profile_digest") != parent.get("profile_digest"):
            return False, f"DELEGATION_PROFILE:{index}", None
        if not _subset(child.get("operations"), parent.get("operations")):
            return False, f"DELEGATION_OPERATIONS:{index}", None
        if not _budgets_attenuate(child.get("budgets"), parent.get("budgets", {})):
            return False, f"DELEGATION_BUDGET:{index}", None
        for field in ("action_digest", "tool_contract_digest", "route_digest"):
            if not _bound_or_narrower(child, parent, field):
                return False, f"DELEGATION_{field.upper()}:{index}", None
        try:
            child_issued = _num(child.get("issued_ms"))
            child_expires = _num(child.get("expires_ms"))
            parent_issued = _num(parent.get("issued_ms"))
            parent_expires = _num(parent.get("expires_ms"))
            if child_issued < parent_issued or child_expires > parent_expires:
                return False, f"DELEGATION_TIME_ATTENUATION:{index}", None
            if child_issued > _num(now_ms) or child_expires <= _num(now_ms):
                return False, f"DELEGATION_TIME:{index}", None
        except ValueError:
            return False, f"DELEGATION_TIME:{index}", None

        parent = child
        parent_digest = digest(child)

    leaf = parent
    executing_agent = envelope.get("agent")
    if edges:
        if leaf.get("delegate") != executing_agent:
            return False, "DELEGATION_LEAF_AGENT", None
    elif leaf.get("agent") != executing_agent:
        return False, "DELEGATION_ROOT_AGENT", None

    action = envelope.get("action", {})
    operation = action.get("operation")
    if operation not in leaf.get("operations", []):
        return False, "DELEGATION_LEAF_OPERATION", None
    if leaf.get("device") != envelope.get("device"):
        return False, "DELEGATION_LEAF_DEVICE", None
    if leaf.get("profile_digest") != envelope.get("profile_digest"):
        return False, "DELEGATION_LEAF_PROFILE", None
    if leaf.get("action_digest") is not None and leaf.get("action_digest") != digest(action):
        return False, "DELEGATION_LEAF_ACTION", None
    if edges and expected_tool_contract_digest is not None:
        if leaf.get("tool_contract_digest") != expected_tool_contract_digest:
            return False, "DELEGATION_TOOL_CONTRACT", None
    if edges and expected_route_digest is not None:
        if leaf.get("route_digest") != expected_route_digest:
            return False, "DELEGATION_ROUTE", None

    return True, None, {
        "leaf_digest": parent_digest,
        "depth": len(edges),
        "leaf": leaf,
    }
