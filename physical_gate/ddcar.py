"""DDC Action Receipt interoperability adapter for physical actions.

This module emits canonical DDCAR v0.1 construction inputs. Cryptographic sealing and
verification remain the responsibility of the DDCAR implementation, so Physical Gate
does not duplicate or fork DDCAR signature semantics.
"""
from datetime import datetime, timezone
from .core import digest

SPEC='https://github.com/altrudev/DDC-Action-Receipt/blob/main/spec/DDC-ACTION-RECEIPT-v0.1.md'
DDCAR_PHYSICAL_SCOPE_MIN_REVISION='909c823dc01121760da8f638080dd233bfedd4a6'

def iso_ms(ms):
    return datetime.fromtimestamp(ms/1000,timezone.utc).isoformat().replace('+00:00','Z')

def sha(obj): return 'sha256:'+digest(obj)

def action(envelope):
    a=envelope['action']
    return {'tool':{'kind':'physical-gate','id':envelope['device'],'version':'0.2',
      'schema_digest':sha({'profile':envelope['profile_digest']})},
      'operation':a['operation'],'parameters':a['parameters']}

def physical_scope(envelope,profile):
    scope={'tool_id':envelope['device'],'operation':envelope['action']['operation']}
    if envelope['action']['operation']=='move':
        scope.update({'frame':'sim-base',
          'workspace':{axis:[str(bounds[0]),str(bounds[1])] for axis,bounds in profile['workspace_mm'].items()},
          'max_speed':str(profile['max_speed_mm_s']),'max_force':str(profile['max_force_N'])})
    return scope

def decision_name(disposition):
    return {'ALLOW':'ALLOW','BLOCK':'BLOCK','REQUIRE HUMAN':'HUMAN-REVIEW','SIMULATE FIRST':'HUMAN-REVIEW'}[disposition]

def construction_inputs(*,envelope,decision,state_signed,profile,principal='human:owner',issuer='ddc-physical-gate'):
    """Return arguments for ddcar.model.make_receipt plus authority scope.

    The caller must use DDCAR authority_grant/sign_authority/seal_decision and,
    after simulated or real execution, bind_execution. This keeps DDCAR signatures
    in one implementation.
    """
    a=action(envelope); issued=decision['evaluated_ms']; expiry=min(envelope['expires_ms'],issued+1000)
    checks=[{'status':'PASS','claim':'physical deterministic gate completed'}]
    assurance={d:{'status':'PASS','claim':'physical profile evidence'}
      for d in ('semantic','authority','state','resource','security','physical','lineage')}
    anomalies=[{'code':f['code'],'severity':'high' if f['disposition']=='BLOCK' else 'medium'}
      for f in decision['findings']]
    scope=physical_scope(envelope,profile)
    return {
      'receipt':{
        'receipt_id':envelope['id'],'nonce':envelope['nonce'],
        'agent':{'id':envelope['agent'],'kind':'agent','version':'unknown'},
        'authority':{'kind':'human','principal':principal,'basis':'signed physical authority grant','scope':scope},
        'tool':a['tool'],'operation':a['operation'],'parameters':a['parameters'],
        'evidence':[{'type':'physical-state','digest':sha(state_signed['payload']),
          'observed_at':iso_ms(state_signed['payload']['observed_ms']),
          'valid_until':iso_ms(state_signed['payload']['valid_until_ms']),
          'source':state_signed['payload']['source']}],
        'policy':{'id':'ddc-physical-gate','version':'0.2','digest':sha({'profile':envelope['profile_digest']})},
        'prerequisites':checks,'permissions':checks,'assurance':assurance,'anomalies':anomalies,
        'risk':{'class':'high' if envelope.get('consequence',0)>=3 else 'medium'},
        'decision':decision_name(decision['disposition']),
        'issuer':{'id':issuer,'kind':'assurance-gate','version':'0.2'},
        'expires_at':iso_ms(expiry),'issued_at':iso_ms(issued)
      },
      'authority_grant':{
        'principal':principal,'scope':scope,'expires_at':iso_ms(expiry),
        'nonce':envelope['nonce'],'issued_at':iso_ms(issued),'agent':envelope['agent'],
        'action_digest':sha(a),'delegation_parent':None
      },
      'interop':{
        'ddcar_version':'0.1','physical_scope_supported':True,
        'minimum_verifier_revision':DDCAR_PHYSICAL_SCOPE_MIN_REVISION,
        'requires_ddcar_signing':True
      }
    }

def make_unsealed_receipt(*,envelope,decision,authority_signed,state_signed,issuer='ddc-physical-gate',profile=None):
    """Backward-compatible structural helper. Prefer construction_inputs()."""
    from .core import PROFILE
    return construction_inputs(envelope=envelope,decision=decision,state_signed=state_signed,
      profile=profile or PROFILE,principal=authority_signed['payload']['principal'],issuer=issuer)
