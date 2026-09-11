# Integration

## DDC Action Receipt

Physical Gate now has an opt-in canonical DDCAR v0.1 bridge pinned to exact accepted source commit `d746e57b6f6a0c4ff6694a1a1ff6954e64f5ef39` (package version 0.1.2; v0.1 wire format unchanged).

The bridge:
- verifies the Physical Gate's independently signed physical authority and state attestations first;
- creates a separate DDCAR human-authority grant bound to the exact DDCAR action digest;
- signs the DDCAR decision with an independently trusted decision key;
- verifies a signed Physical Gate simulated execution before binding a separate DDCAR execution claim;
- records simulation explicitly as `simulation-only:physical-gate`;
- never treats DDCAR verification as proof that real hardware moved.

DDCAR v0.1's reference scope language does not natively express Physical Gate's frame/workspace/speed/force policy fields. Those richer constraints remain enforced by Physical Gate and are bound through the exact action digest, profile/policy digest, and physical evidence. The canonical DDCAR scope is intentionally limited to `tool_id` + `operation` rather than silently extending the v0.1 verifier vocabulary.

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
