# DDC Physical Gate

Independent, vendor-neutral pre-execution assurance for AI-to-physical-device commands.

**Status:** v0.2 simulation-only research reference. No real-hardware transport is included or enabled.

DDC Physical Gate evaluates whether an exact proposed physical action should be allowed to cross the hardware boundary given the current observed state, authority, device profile, deterministic physical constraints, uncertainty, sequence, and policy.

It returns one of:

- `ALLOW`
- `BLOCK`
- `REQUIRE HUMAN`
- `SIMULATE FIRST`

It is **not** a motion planner, safety PLC, emergency-stop system, certified functional-safety component, or replacement for manufacturer interlocks.

## Design boundary

The public reference separates:

1. deterministic physical constraints that cannot be overridden by probabilistic reasoning;
2. review/simulation escalation signals;
3. exact action and state commitments;
4. independent executor re-checking;
5. signed decision and simulated execution evidence;
6. replay protection;
7. signed human-authority grants;
8. signed device-state attestations;
9. independent cryptographic revalidation at dispatch;
10. simulation-only MCP and MHS-shaped adapter normalization.

The proprietary DDC assurance methodology is not included.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .[test]
python -m pytest -q
python -m physical_gate.cli demo
```

## DSR verification

The reference implementation at commit:

`45009e1f1783797911d981efe750f7c30b47bf56`

was executed through DDC Remote Executor / DSR with DDC radial admission.

Result:

```text
58 passed in 0.33s
exit_code: 0
radial_outcome: ALLOW
status: PASS
worker: vps-377a113a-slot2
```

DSR job: `b62e4c7193a84f1aa0d5c8e2479f613b`

## Safety model

The simulator covers stale observations, impossible coordinates, conflicting observations, unsafe state transitions, invalid units and frames, excessive speed/force, missing prerequisites, authority failures, interlock failures, malformed values, replay, state drift, and adversarial override instructions.

A signed `ALLOW` is not sufficient by itself. The executor independently verifies the signature, exact action, exact state commitment, permit expiry, deterministic gate result, and nonce reservation before simulated dispatch.

## Integration direction

DDC Physical Gate is intended to sit above device-native safety layers and below autonomous agents:

```text
Agent / MCP / MHS / API
        |
        v
DDC Physical Gate
        |
        v
device adapter / controller
        |
        v
certified safety / interlocks / hardware
```

DDC Action Receipt provides the evidence protocol direction. The current physical receipt is explicitly a draft profile and does not claim full schema interoperability yet.

See `docs/ARCHITECTURE.md`, `docs/INTEGRATION.md`, and `docs/RELEASE-GATES.md`.

## Critical limitation

Do not connect this repository directly to robots, laboratory instruments, manufacturing equipment, vehicles, or other physical systems. Real hardware requires trusted device identity, attested sensor provenance, validated trajectory or process constraints, site-specific safety analysis, certified safety controls where applicable, and independent verification.


## v0.2 trust boundary

The v0.2 path adds `SecureGate` and `SecureExecutor`. Human authority is signed and bound to the exact agent, device, nonce, profile, action digest and expiry. Device state is separately signed and bound to the exact snapshot digest, device generation, observation time, profile and evidence source.

The secure executor independently revalidates both proofs before simulated dispatch. This prevents the admission layer from becoming the sole trust decision point.

The repository also includes simulation-only normalizers for MCP-shaped and MHS-research-shaped requests. The MHS adapter is deliberately labeled as a research compatibility shape, not an official Anthropic schema.

DDC Action Receipt v0.1 structural mapping is implemented, but its current core verifier does not yet define physical-device authority scopes. The repository reports this as an explicit interoperability limitation rather than claiming full verifier compatibility.
