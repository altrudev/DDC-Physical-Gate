"""DDC Action Receipt interoperability for Physical Gate.

Physical Gate remains authoritative for physical preconditions in this simulation-only
reference. DDCAR supplies a portable, independently verifiable action-evidence envelope.
The two signature domains are intentionally distinct.
"""
from datetime import datetime, timezone

from .core import canonical, digest
from .trust import verify_authority, verify_state

SPEC='https://github.com/altrudev/DDC-Action-Receipt/blob/main/spec/DDC-ACTION-RECEIPT-v0.1.md'
DDCAR_ACCEPTED_REVISION='d746e57b6f6a0c4ff6694a1a1ff6954e64f5ef39'
# Compatibility alias retained for callers that used the older constant.
DDCAR_PHYSICAL_SCOPE_MIN_REVISION=DDCAR_ACCEPTED_REVISION


def iso_ms(ms):
    return datetime.fromtimestamp(ms/1000,timezone.utc).isoformat().replace('+00:00','Z')


def sha(obj):
    return 'sha256:'+digest(obj)


def action(envelope):
    a=envelope['action']
    return {'tool':{'kind':'physical-gate','id':envelope['device'],'version':'0.2',
      'schema_digest':sha({'profile':envelope['profile_digest']})},
      'operation':a['operation'],'parameters':a['parameters']}


def canonical_authority_scope(envelope):
    """Scope vocabulary supported directly by the DDCAR v0.1 reference verifier.

    Rich physical limits remain independently enforced by Physical Gate and are bound
    through the exact action digest, profile/policy digest and physical evidence.
    """
    return {'tool_id':envelope['device'],'operation':envelope['action']['operation']}


def physical_scope(envelope,profile):
    """Physical Gate policy scope; this is NOT silently inserted into DDCAR v0.1 scope."""
    scope={'tool_id':envelope['device'],'operation':envelope['action']['operation']}
    if envelope['action']['operation']=='move':
        scope.update({'frame':'sim-base',
          'workspace':{axis:[str(bounds[0]),str(bounds[1])] for axis,bounds in profile['workspace_mm'].items()},
          'max_speed':str(profile['max_speed_mm_s']),'max_force':str(profile['max_force_N'])})
    return scope


def decision_name(disposition):
    return {'ALLOW':'ALLOW','BLOCK':'BLOCK','REQUIRE HUMAN':'HUMAN-REVIEW','SIMULATE FIRST':'HUMAN-REVIEW'}[disposition]


def _checks(decision):
    allowed=decision.get('disposition')=='ALLOW'
    status='PASS' if allowed else 'UNRESOLVED'
    checks=[{'status':status,'claim':'physical deterministic gate completed'}]
    assurance={d:{'status':'PASS' if allowed or d!='physical' else 'UNRESOLVED',
                  'claim':'Physical Gate evidence'}
      for d in ('semantic','authority','state','resource','security','physical','lineage')}
    return checks,assurance


def construction_inputs(*,envelope,decision,state_signed,profile,principal='human:owner',issuer='ddc-physical-gate'):
    """Return dependency-free structural inputs for DDCAR construction.

    This preview uses only the DDCAR v0.1-supported authority scope. The richer
    Physical Gate policy scope is exposed separately in interop metadata.
    Cryptographic signing must use build_decision_receipt(), not these preview fields.
    """
    a=action(envelope); issued=decision['evaluated_ms']; expiry=min(envelope['expires_ms'],issued+1000)
    checks,assurance=_checks(decision)
    anomalies=[{'code':f['code'],'severity':'high' if f['disposition']=='BLOCK' else 'medium'}
      for f in decision['findings']]
    scope=canonical_authority_scope(envelope)
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
        'policy':{'id':'ddc-physical-gate','version':'0.3','digest':sha({'profile':envelope['profile_digest']})},
        'prerequisites':checks,'permissions':checks,'assurance':assurance,'anomalies':anomalies,
        'risk':{'class':'high' if envelope.get('consequence',0)>=3 else 'medium'},
        'decision':decision_name(decision['disposition']),
        'issuer':{'id':issuer,'kind':'assurance-gate','version':'0.3'},
        'expires_at':iso_ms(expiry),'issued_at':iso_ms(issued)
      },
      'authority_grant':{
        'principal':principal,'scope':scope,'expires_at':iso_ms(expiry),
        'nonce':envelope['nonce'],'issued_at':iso_ms(issued),'agent':envelope['agent'],
        'action_digest':sha(a),'delegation_parent':None
      },
      'interop':{
        'ddcar_version':'0.1','accepted_ddcar_revision':DDCAR_ACCEPTED_REVISION,
        'physical_scope':physical_scope(envelope,profile),
        'physical_scope_enforced_by':'ddc-physical-gate',
        'canonical_ddcar_scope':scope,
        'requires_ddcar_signing':True
      }
    }


def build_decision_receipt(*,envelope,snapshot,decision,physical_authority_signed,state_signed,
                           physical_authority_trust,state_trust,ddcar_trust,
                           ddcar_authority_private,authority_key_id,
                           ddcar_decision_private,decision_key_id,
                           profile,principal='human:owner',issuer='ddc-physical-gate'):
    """Build, seal and self-verify a canonical DDCAR decision receipt.

    Physical authority/state proofs are verified first. DDCAR then signs a separate
    exact-action authority grant and decision commitment. This function has no device
    I/O and does not execute the requested action.
    """
    from ddcar.crypto import public_from_private, sha256_bytes, sha256_digest
    from ddcar.model import authority_grant, sign_authority, make_receipt, seal_decision, verify_receipt

    now_ms=decision['evaluated_ms']
    ok,code=verify_authority(physical_authority_signed,physical_authority_trust,envelope=envelope,now_ms=now_ms)
    if not ok: raise ValueError('physical authority verification failed: '+str(code))
    ok,code=verify_state(state_signed,state_trust,snapshot=snapshot,now_ms=now_ms)
    if not ok: raise ValueError('physical state verification failed: '+str(code))
    if decision.get('action_digest')!=digest(envelope['action']): raise ValueError('decision action mismatch')
    if decision.get('snapshot_digest')!=digest(snapshot): raise ValueError('decision snapshot mismatch')
    if decision.get('profile_digest')!=digest(profile): raise ValueError('decision profile mismatch')

    if ddcar_trust.get('authority',{}).get(authority_key_id)!=public_from_private(ddcar_authority_private):
        raise ValueError('DDCAR authority signing key not trusted')
    if ddcar_trust.get('decision',{}).get(decision_key_id)!=public_from_private(ddcar_decision_private):
        raise ValueError('DDCAR decision signing key not trusted')
    if ddcar_trust.get('bindings',{}).get('authority',{}).get(authority_key_id)!=principal:
        raise ValueError('DDCAR authority key/principal binding mismatch')
    if ddcar_trust.get('bindings',{}).get('decision',{}).get(decision_key_id)!=issuer:
        raise ValueError('DDCAR decision key/issuer binding mismatch')

    preview=construction_inputs(envelope=envelope,decision=decision,state_signed=state_signed,
                                profile=profile,principal=principal,issuer=issuer)
    r=preview['receipt']
    exact=action(envelope)
    exact_digest=sha256_digest(exact)
    grant=authority_grant(principal,canonical_authority_scope(envelope),r['expires_at'],
                          envelope['nonce'],issued_at=r['issued_at'],agent=envelope['agent'],
                          action_digest=exact_digest)
    proof=sign_authority(grant,ddcar_authority_private,authority_key_id)

    # Bind both independently verified Physical Gate trust objects as immutable evidence.
    r['evidence']=[
      {'type':'physical-state-attestation',
       'digest':sha256_bytes(canonical(state_signed)),
       'observed_at':iso_ms(state_signed['payload']['observed_ms']),
       'valid_until':iso_ms(state_signed['payload']['valid_until_ms']),
       'source':state_signed['payload']['source']},
      {'type':'physical-authority-proof',
       'digest':sha256_bytes(canonical(physical_authority_signed)),
       'observed_at':iso_ms(physical_authority_signed['payload']['issued_ms']),
       'valid_until':iso_ms(physical_authority_signed['payload']['expires_ms']),
       'source':'physical-gate-authority'}
    ]
    receipt=make_receipt(receipt_id=r['receipt_id'],nonce=r['nonce'],agent=r['agent'],
        authority=r['authority'],authority_grant=grant,authority_proof=proof,
        tool=r['tool'],operation=r['operation'],parameters=r['parameters'],
        evidence=r['evidence'],policy=r['policy'],prerequisites=r['prerequisites'],
        permissions=r['permissions'],assurance=r['assurance'],anomalies=r['anomalies'],
        risk=r['risk'],decision=r['decision'],issuer=r['issuer'],
        expires_at=r['expires_at'],issued_at=r['issued_at'])
    receipt=seal_decision(receipt,ddcar_decision_private,decision_key_id)
    errors=verify_receipt(receipt,trust=ddcar_trust,mode='preflight',require_execution=False,
                          now=datetime.fromtimestamp(now_ms/1000,timezone.utc))
    if errors: raise ValueError('DDCAR decision verification failed: '+'; '.join(errors))
    return receipt


def bind_simulated_execution(receipt,*,envelope,physical_execution_signed,physical_execution_trust,
                             ddcar_trust,ddcar_execution_private,execution_key_id,
                             executor_id='physical-gate-simulator'):
    """Bind a verified simulation result as the DDCAR execution claim.

    This does not represent real hardware execution. The Physical Gate execution
    signature is verified first and its signed object is committed as outcome evidence.
    """
    from ddcar.crypto import public_from_private, sha256_bytes
    from ddcar.model import bind_execution, verify_receipt
    from .core import verify

    if not verify(physical_execution_signed,physical_execution_trust):
        raise ValueError('untrusted physical execution claim')
    p=physical_execution_signed.get('payload',{})
    if p.get('status')!='SIMULATED': raise ValueError('only simulated execution is supported')
    if p.get('device')!=envelope.get('device') or p.get('nonce')!=envelope.get('nonce'):
        raise ValueError('physical execution binding mismatch')
    if p.get('action_digest')!=digest(envelope.get('action')):
        raise ValueError('physical execution action mismatch')
    if ddcar_trust.get('execution',{}).get(execution_key_id)!=public_from_private(ddcar_execution_private):
        raise ValueError('DDCAR execution signing key not trusted')
    if ddcar_trust.get('bindings',{}).get('execution',{}).get(execution_key_id)!=executor_id:
        raise ValueError('DDCAR execution key/executor binding mismatch')

    exact=action(envelope)
    final=bind_execution(receipt,tool=exact['tool'],operation=exact['operation'],
        parameters=exact['parameters'],
        outcome={'status':'SUCCEEDED','evidence_digest':sha256_bytes(canonical(physical_execution_signed)),
                 'reference':'simulation-only:physical-gate'},
        executor={'id':executor_id,'kind':'simulator','version':'0.3'},
        private_key=ddcar_execution_private,key_id=execution_key_id,
        observed_at=iso_ms(p['completed_ms']))
    errors=verify_receipt(final,trust=ddcar_trust,mode='historical',
                          now=datetime.fromtimestamp(p['completed_ms']/1000,timezone.utc))
    if errors: raise ValueError('DDCAR execution verification failed: '+'; '.join(errors))
    return final


def make_unsealed_receipt(*,envelope,decision,authority_signed,state_signed,issuer='ddc-physical-gate',profile=None):
    """Backward-compatible structural helper. Prefer build_decision_receipt()."""
    from .core import PROFILE
    return construction_inputs(envelope=envelope,decision=decision,state_signed=state_signed,
      profile=profile or PROFILE,principal=authority_signed['payload']['principal'],issuer=issuer)
