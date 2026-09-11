# Architecture

## Objective

Answer one narrow question before a physical command is allowed to proceed:

> Should this exact proposed physical action be allowed to reach this device, given the current state of the world?

## Layers

### Command envelope
Binds the exact agent, device, action, parameters, units, coordinate frame, nonce, timing, authority, device generation, consequence, reversibility, device profile digest, and observed-state digest.

### Deterministic gate
Fail-closed checks cover identity and capability matching, state freshness, required sensors, interlocks, workspace limits, unit/frame correctness, speed/force limits, sequence prerequisites, resource conflicts, state-machine state, and malformed/non-finite inputs.

Hard deterministic failures always dominate review or simulation suggestions.

### Escalation layer
Higher consequence, irreversibility, unresolved uncertainty, repeated retries, historical/radial anomalies, and other non-hard findings may yield `REQUIRE HUMAN`.

Missing or stale trajectory/simulation evidence may yield `SIMULATE FIRST`.

### Evidence
Each decision commits to the exact action, snapshot, profile, and evaluation time. Ed25519 signatures provide integrity and signer attribution when trust anchors are established independently.

### Independent executor
The executor does not trust `ALLOW` blindly. It verifies the decision signature, action digest, state digest, permit time, deterministic gate result, and nonce uniqueness before simulated execution.

## Non-goals

This project does not implement:
- motion planning;
- collision-free trajectory generation;
- safety PLC logic;
- certified functional safety;
- emergency-stop behavior;
- device firmware protections;
- physical outcome proof.

Those remain independent safety layers and evidence sources.

## Radial-frequency boundary

Public code exposes only the resulting assurance interfaces and explicit findings. Proprietary DDC radial-frequency methodology and internal scoring/reasoning are not part of this repository.
