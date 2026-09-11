# Release Gates

Real-hardware support is prohibited until all applicable gates are satisfied.

## Required before shadow mode
- canonical schemas and validation;
- independently verifiable authority grants;
- trusted device identity;
- signed or otherwise attested sensor/state provenance;
- robust clock/freshness model;
- durable replay/idempotency handling;
- crash-recovery and unknown-outcome reconciliation;
- actual DDC Action Receipt interoperability;
- explicit policy/profile versioning;
- adversarial and malformed-input testing.

## Required before supervised hardware trial
- read-only/shadow deployment completed first;
- device-specific validated adapter;
- independent trajectory/process validator where relevant;
- site-specific hazard analysis;
- manufacturer safety limits preserved;
- certified safety system remains independent where required;
- physical emergency stop outside agent control;
- bounded force/speed/energy;
- human authorization procedure;
- rollback and incident-response plan;
- independent test and safety review.

## Never acceptable
- model output overriding a hard safety failure;
- agent self-attestation as sole authority;
- stale state treated as current;
- unsigned policy/profile substitution;
- hidden unit conversion;
- a single opaque model deciding both safety and execution;
- DDC being presented as a certified safety controller without applicable certification.
