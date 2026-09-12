"""v0.4 MCP shadow-mode assurance boundary.

Accepts MCP-shaped tool calls plus signed authority/state evidence, normalizes them,
runs the proof-bound Physical Gate, and emits a signed decision plus DDCAR preview.
It deliberately has no transport, dispatch, ROS, serial, GPIO, SDK or device-write path.
"""
from copy import deepcopy

from .adapters import from_mcp, AdapterError
from .core import PROFILE, digest
from .ddcar import construction_inputs
from .secure_gate import SecureGate, issue_secure

SHADOW_SCHEMA='ddc.physical-mcp-shadow/0.4'

class ShadowModeError(ValueError):
    pass

class MCPShadowBoundary:
    def __init__(self, *, decision_signer, authority_trust, state_trust,
                 profile=None, authority_revocations=None, state_lineage=None):
        self.profile=profile or PROFILE
        self.decision_signer=decision_signer
        self.gate=SecureGate(profile=self.profile,authority_trust=authority_trust,
          state_trust=state_trust,authority_revocations=authority_revocations,
          state_lineage=state_lineage)

    def evaluate(self, request, snapshot, now_ms, *, authority_proof, state_proof,
                 simulation=None, history=None):
        try:
            envelope=from_mcp(request,snapshot,self.profile)
        except AdapterError as exc:
            raise ShadowModeError(str(exc)) from exc
        signed=issue_secure(self.gate,envelope,snapshot,self.decision_signer,now_ms,
          authority_proof=authority_proof,state_proof=state_proof,
          simulation=simulation,history=history)
        decision=signed['payload']
        preview=construction_inputs(envelope=envelope,decision=decision,
          state_signed=state_proof,profile=self.profile,
          principal=authority_proof.get('payload',{}).get('principal','unknown'))
        return {
          'schema':SHADOW_SCHEMA,
          'mode':'SHADOW',
          'request_id':envelope['id'],
          'device':envelope['device'],
          'action_digest':decision['action_digest'],
          'snapshot_digest':decision['snapshot_digest'],
          'profile_digest':decision['profile_digest'],
          'decision':decision['disposition'],
          'findings':deepcopy(decision.get('findings',[])),
          'signed_decision':signed,
          'ddcar_preview':preview,
          'dispatch':{
            'available':False,
            'permitted':False,
            'reason':'shadow-mode-no-transport'
          },
          'hardware_write_capability':False
        }

def assert_shadow_only(result):
    """Fail closed if a caller attempts to treat a shadow result as executable."""
    if result.get('schema')!=SHADOW_SCHEMA or result.get('mode')!='SHADOW':
        raise ShadowModeError('not a shadow result')
    dispatch=result.get('dispatch',{})
    if dispatch.get('available') or dispatch.get('permitted') or result.get('hardware_write_capability'):
        raise ShadowModeError('shadow boundary exposed dispatch capability')
    return True
