# Integration

## DDC Action Receipt

The simulator emits a draft `ddcar.physical.v0.1-draft` profile containing:
- exact envelope commitment;
- signed gate decision;
- signed simulated execution claim;
- snapshot and profile commitments;
- simulated outcome claim.

This is intentionally marked draft until it is mapped to and validated against the canonical DDC Action Receipt schema and verifier.

## MHS / MCP

Future adapters should translate external tool or hardware commands into the vendor-neutral command envelope before admission.

An adapter must never:
- treat transport authentication as physical safety approval;
- drop units, frames, timing, or state generation;
- bypass manufacturer safety limits;
- silently coerce malformed values;
- convert `REQUIRE HUMAN` or `SIMULATE FIRST` into `ALLOW`.

## ROS 2

ROS 2 integration should be an adapter boundary, not a replacement safety controller. The gate may accept ROS-derived state and emit an admitted command, while native controllers, limits, collision systems, and functional-safety components remain authoritative for their domains.

## Trust requirements before hardware

Production adapters require independently established:
- human/organization authority;
- agent identity;
- device identity;
- device profile/version;
- sensor provenance;
- monotonic/fresh time evidence;
- state generation;
- policy version;
- execution identity;
- postcondition evidence.
