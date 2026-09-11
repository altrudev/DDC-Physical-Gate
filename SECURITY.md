# Security Policy

DDC Physical Gate is a simulation-only research reference.

Do not connect it to real hardware, production control networks, safety-critical systems, or consequential physical processes.

Report security issues privately to the repository owner rather than publishing exploit details before remediation.

Key security invariants:
- hard deterministic constraints dominate;
- action and state are digest-bound;
- execution requires independent signature verification and re-check;
- nonces are reserved before simulated effects;
- malformed/non-finite inputs fail closed;
- real-hardware transport is explicitly unavailable.
