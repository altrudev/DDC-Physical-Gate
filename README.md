# DDC Physical Gate

An experimental, vendor-neutral, simulation-only physical-action assurance reference.

DDC Physical Gate evaluates whether an exact proposed agent action is admissible against current evidence, authority, device capabilities, deterministic constraints, and policy. It is not a certified safety system, motion planner, safety PLC, or replacement for hardware interlocks. No real-hardware execution is enabled.

The reference implementation and research package are being prepared for publication. The public protocol and verifier will remain independent of proprietary DDC methodology. DDC Action Receipt integration is planned; the current physical receipt profile is a draft, not a claim of interoperability.

## Safety status

Do not connect this prototype to physical equipment or use its decisions as production safety authorization. Any real-hardware deployment requires independent verification, trusted authority and device evidence, a site-specific safety case, and appropriate certified safety controls.

## Project scope

- Exact-action and state-bound admission decisions.
- Deterministic constraints that probabilistic reasoning cannot override.
- Signed decision and simulated execution evidence.
- Replay protection and independent executor rechecking.
- Simulated faults, adversarial tests, and documented release gates.
- Future MCP, MHS, and ROS 2 adapters without bypassing device safety systems.

License and contribution terms for the reference implementation will be published with the source. Proprietary DDC internals are not included.