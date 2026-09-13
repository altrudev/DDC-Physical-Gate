"""v0.5 candidate: execution-time authority continuity, tool drift, and route closure.

This is an additive profile. It does not alter the stable v0.4 classes.
"""
from __future__ import annotations

from .authority_continuity import verify_delegation_chain
from .contracts_v05 import route_digest, tool_contract_digest, verify_route
from .core import digest, sign, verify
from .secure_gate import SecureGate
from .secure_runtime import SecureExecutor
from .trust import AUTHORITY_VERSION, verify_state


TRUST_PROFILE = "cryptographic-v0.5"


def _verify_root_authority(signed, trusted, *, envelope, now_ms, revoked=None):
    if not verify(signed, trusted):
        return False, "ROOT_AUTHORITY_SIGNATURE"
    grant = signed.get("payload", {})
    if grant.get("version") != AUTHORITY_VERSION:
        return False, "ROOT_AUTHORITY_VERSION"
    if revoked is not None and digest(grant) in revoked:
        return False, "ROOT_AUTHORITY_REVOKED"
    if grant.get("device") != envelope.get("device"):
        return False, "ROOT_AUTHORITY_DEVICE"
    if grant.get("profile_digest") != envelope.get("profile_digest"):
        return False, "ROOT_AUTHORITY_PROFILE"
    operation = envelope.get("action", {}).get("operation")
    if operation not in grant.get("operations", []):
        return False, "ROOT_AUTHORITY_OPERATION"
    if grant.get("action_digest") is not None and grant.get("action_digest") != digest(envelope.get("action", {})):
        return False, "ROOT_AUTHORITY_ACTION"
    try:
        if grant.get("issued_ms") > now_ms or grant.get("expires_ms") <= now_ms:
            return False, "ROOT_AUTHORITY_TIME"
    except TypeError:
        return False, "ROOT_AUTHORITY_TIME"
    return True, None


class SecureGateV05(SecureGate):
    def __init__(
        self,
        *,
        profile=None,
        authority_trust=None,
        state_trust=None,
        route_trust=None,
        authority_revocations=None,
        delegation_revocations=None,
        state_lineage=None,
        gate_id="physical-gate",
        executor_id="physical-executor",
        entrypoint_digest=None,
        closure_evidence_digest=None,
        enforcement_digest=None,
    ):
        super().__init__(
            profile=profile,
            authority_trust=authority_trust,
            state_trust=state_trust,
            authority_revocations=authority_revocations,
            state_lineage=state_lineage,
        )
        self.route_trust = route_trust or {}
        self.delegation_revocations = (
            delegation_revocations if delegation_revocations is not None else set()
        )
        self.gate_id = gate_id
        self.executor_id = executor_id
        self.entrypoint_digest = entrypoint_digest
        self.closure_evidence_digest = closure_evidence_digest
        self.enforcement_digest = enforcement_digest

    def evaluate_v05(
        self,
        envelope,
        snapshot,
        now_ms,
        *,
        root_authority_proof,
        delegation_chain,
        state_proof,
        tool_contract,
        route_proof,
        simulation=None,
        history=None,
    ):
        base = self.gate.evaluate(envelope, snapshot, now_ms, simulation, history)
        findings = list(base.get("findings", []))

        def block(code):
            findings.append({"code": code, "disposition": "BLOCK"})

        try:
            contract_digest = tool_contract_digest(tool_contract)
        except (TypeError, ValueError):
            contract_digest = None
            block("TOOL_CONTRACT_INVALID")

        ok, code = _verify_root_authority(
            root_authority_proof or {},
            self.authority_trust,
            envelope=envelope,
            now_ms=now_ms,
            revoked=self.authority_revocations,
        )
        if not ok:
            block(code)

        route_ok = False
        route_binding = None
        if contract_digest is not None:
            route_ok, code = verify_route(
                route_proof or {},
                self.route_trust,
                envelope=envelope,
                now_ms=now_ms,
                expected_tool_contract_digest=contract_digest,
                expected_gate_id=self.gate_id,
                expected_executor_id=self.executor_id,
                expected_entrypoint_digest=self.entrypoint_digest,
                expected_closure_evidence_digest=self.closure_evidence_digest,
                expected_enforcement_digest=self.enforcement_digest,
            )
            if not route_ok:
                block(code)
            else:
                route_binding = route_digest(route_proof)

        if ok:
            ok, code, continuity = verify_delegation_chain(
                delegation_chain,
                self.authority_trust,
                root_authority=root_authority_proof.get("payload", {}),
                envelope=envelope,
                now_ms=now_ms,
                revoked=self.delegation_revocations,
                expected_tool_contract_digest=contract_digest,
                expected_route_digest=route_binding,
            )
            if not ok:
                block(code)
        else:
            continuity = None

        ok_state, state_code = verify_state(
            state_proof or {},
            self.state_trust,
            snapshot=snapshot,
            now_ms=now_ms,
        )
        if not ok_state:
            block(state_code)
        elif self.state_lineage is not None:
            ok_state, state_code = self.state_lineage.check(state_proof)
            if not ok_state:
                block(state_code)

        base["findings"] = findings
        if any(item["disposition"] == "BLOCK" for item in findings):
            base["disposition"] = "BLOCK"
        base.update(
            {
                "trust_profile": TRUST_PROFILE,
                "tool_contract_digest": contract_digest,
                "route_proof_digest": digest(route_proof or {}),
                "delegation_chain_digest": digest(list(delegation_chain or [])),
                "authority_continuity": continuity,
            }
        )
        return base


def issue_secure_v05(
    gate,
    envelope,
    snapshot,
    key,
    now_ms,
    *,
    root_authority_proof,
    delegation_chain,
    state_proof,
    tool_contract,
    route_proof,
    simulation=None,
    history=None,
):
    decision = gate.evaluate_v05(
        envelope,
        snapshot,
        now_ms,
        root_authority_proof=root_authority_proof,
        delegation_chain=delegation_chain,
        state_proof=state_proof,
        tool_contract=tool_contract,
        route_proof=route_proof,
        simulation=simulation,
        history=history,
    )
    decision.update(
        {
            "envelope_digest": digest(envelope),
            "expires_ms": min(
                envelope.get("expires_ms", now_ms),
                now_ms + gate.profile["max_permit_ms"],
            ),
            "root_authority_proof_digest": digest(root_authority_proof),
            "state_proof_digest": digest(state_proof),
            "trust_profile": TRUST_PROFILE,
        }
    )
    return sign(key, decision)


class SecureExecutorV05(SecureExecutor):
    """Executor that re-establishes authority, state, tool, and route validity."""

    def __init__(
        self,
        simulator,
        ledger,
        decision_trust,
        signer,
        *,
        authority_trust,
        state_trust,
        route_trust,
        authority_revocations=None,
        delegation_revocations=None,
        state_lineage=None,
        gate_id="physical-gate",
        executor_id="physical-executor",
        entrypoint_digest=None,
        closure_evidence_digest=None,
        enforcement_digest=None,
    ):
        super().__init__(
            simulator,
            ledger,
            decision_trust,
            signer,
            authority_trust=authority_trust,
            state_trust=state_trust,
            authority_revocations=authority_revocations,
            state_lineage=state_lineage,
        )
        self.gate_v05 = SecureGateV05(
            authority_trust=authority_trust,
            state_trust=state_trust,
            route_trust=route_trust,
            authority_revocations=authority_revocations,
            delegation_revocations=delegation_revocations,
            state_lineage=state_lineage,
            gate_id=gate_id,
            executor_id=executor_id,
            entrypoint_digest=entrypoint_digest,
            closure_evidence_digest=closure_evidence_digest,
            enforcement_digest=enforcement_digest,
        )

    def dispatch_secure_v05(
        self,
        envelope,
        decision,
        *,
        root_authority_proof,
        delegation_chain,
        state_proof,
        tool_contract,
        route_proof,
        approved_action=None,
    ):
        if not verify(decision, self.trusted):
            raise ValueError("untrusted decision")
        payload = decision["payload"]
        now_ms = self.sim.now
        if payload.get("disposition") != "ALLOW":
            raise ValueError("not allowed")
        if payload.get("trust_profile") != TRUST_PROFILE:
            raise ValueError("decision lacks v0.5 continuity binding")
        if payload.get("envelope_digest") != digest(envelope):
            raise ValueError("envelope changed")
        if payload.get("expires_ms", 0) <= now_ms or payload.get("evaluated_ms", now_ms + 1) > now_ms:
            raise ValueError("permit expired")
        if payload.get("root_authority_proof_digest") != digest(root_authority_proof):
            raise ValueError("root authority proof substitution")
        if payload.get("state_proof_digest") != digest(state_proof):
            raise ValueError("state proof substitution")
        if payload.get("delegation_chain_digest") != digest(list(delegation_chain or [])):
            raise ValueError("delegation chain substitution")
        if payload.get("route_proof_digest") != digest(route_proof or {}):
            raise ValueError("route proof substitution")
        if payload.get("tool_contract_digest") != tool_contract_digest(tool_contract):
            raise ValueError("tool contract drift")
        approved = approved_action if approved_action is not None else envelope["action"]
        if payload.get("action_digest") != digest(approved):
            raise ValueError("action changed")

        snapshot = self.sim.snapshot()
        if payload.get("snapshot_digest") != digest(snapshot):
            raise ValueError("state changed")

        check = self.gate_v05.evaluate_v05(
            envelope,
            snapshot,
            now_ms,
            root_authority_proof=root_authority_proof,
            delegation_chain=delegation_chain,
            state_proof=state_proof,
            tool_contract=tool_contract,
            route_proof=route_proof,
        )
        if check["disposition"] != "ALLOW":
            raise ValueError("v0.5 execution-time recheck failed")
        if check["profile_digest"] != payload["profile_digest"]:
            raise ValueError("profile changed")

        if self.state_lineage is not None:
            ok, code = self.state_lineage.accept(state_proof)
            if not ok:
                raise ValueError("state lineage: " + code)

        if not self.ledger.reserve(envelope["nonce"], payload["action_digest"]):
            raise ValueError("replay")

        import copy

        before = digest(snapshot)
        try:
            outcome = self.sim.execute(copy.deepcopy(envelope["action"]))
            self.ledger.finish(envelope["nonce"], "COMPLETED")
        except BaseException:
            self.ledger.finish(envelope["nonce"], "UNKNOWN")
            raise

        return sign(
            self.signer,
            {
                "version": "ddc.physical-execution.v0.5",
                "decision_digest": digest(payload),
                "root_authority_proof_digest": digest(root_authority_proof),
                "delegation_chain_digest": digest(list(delegation_chain or [])),
                "state_proof_digest": digest(state_proof),
                "tool_contract_digest": payload["tool_contract_digest"],
                "route_proof_digest": payload["route_proof_digest"],
                "action_digest": payload["action_digest"],
                "before_digest": before,
                "after_digest": digest(outcome),
                "status": "SIMULATED",
                "device": envelope["device"],
                "nonce": envelope["nonce"],
                "generation_before": snapshot["generation"],
                "generation_after": outcome["generation"],
                "completed_ms": self.sim.now,
            },
        )
