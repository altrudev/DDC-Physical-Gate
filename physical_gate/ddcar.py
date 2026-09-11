"""Mapping to the public DDC Action Receipt v0.1 structure.

Physical authority scopes are not yet accepted by the current DDCAR v0.1
payment-oriented scope evaluator. Structural compatibility and verifier
compatibility are therefore reported separately.
"""
from datetime import datetime, timezone
from .core import digest

SPEC='https://github.com/altrudev/DDC-Action-Receipt/blob/main/spec/DDC-ACTION-RECEIPT-v0.1.md'

def iso_ms(ms):
    return datetime.fromtimestamp(ms/1000,timezone.utc).isoformat().replace('+00:00','Z')

def sha(obj): return 'sha256:'+digest(obj)

def action(envelope):
    a=envelope['action']
    return {'tool':{'kind':'physical-gate','id':envelope['device'],'version':'0.2','schema_digest':sha({'profile':envelope['profile_digest']})},
            'operation':a['operation'],'parameters':a['parameters']}

def decision_name(disposition):
    return {'ALLOW':'ALLOW','BLOCK':'BLOCK','REQUIRE HUMAN':'HUMAN-REVIEW','SIMULATE FIRST':'HUMAN-REVIEW'}[disposition]

def make_unsealed_receipt(*,envelope,decision,authority_signed,state_signed,issuer='ddc-physical-gate'):
    a=action(envelope); issued=decision['evaluated_ms']; expiry=min(envelope['expires_ms'],issued+1000)
    checks=[{'status':'PASS','claim':'physical deterministic gate completed'}]
    assurance={d:{'status':'PASS','claim':'physical profile evidence'} for d in ('semantic','authority','state','resource','security','physical','lineage')}
    anomalies=[{'code':f['code'],'severity':'high' if f['disposition']=='BLOCK' else 'medium'} for f in decision['findings']]
    risk={'class':'high' if envelope.get('consequence',0)>=3 else 'medium'}
    grant=authority_signed['payload']
    scope={'tool_id':envelope['device'],'operation':a['operation']}
    receipt={'spec':SPEC,'version':'0.1','receipt_id':envelope['id'],'issued_at':iso_ms(issued),'expires_at':iso_ms(expiry),
      'nonce':envelope['nonce'],'agent':{'id':envelope['agent'],'kind':'agent','version':'unknown'},
      'authority':{'kind':'human','principal':grant['principal'],'basis':'signed physical authority grant','scope':scope},
      'authority_grant':None,'authority_proof':None,'requested_action':a,'requested_action_digest':sha(a),
      'evidence':[{'type':'physical-state','digest':sha(state_signed['payload']),'observed_at':iso_ms(state_signed['payload']['observed_ms']),
                   'valid_until':iso_ms(state_signed['payload']['valid_until_ms']),'source':state_signed['payload']['source']}],
      'policy':{'id':'ddc-physical-gate','version':'0.2','digest':sha({'profile':envelope['profile_digest']})},
      'prerequisites':checks,'permissions':checks,'assurance':assurance,'anomalies':anomalies,'risk':risk,
      'decision':decision_name(decision['disposition']),'issuer':{'id':issuer,'kind':'assurance-gate','version':'0.2'},
      'lineage':{'previous':[],'delegation_parent':None},'decision_proof':None,'execution':None,'execution_proof':None}
    return {'receipt':receipt,'interop':{'ddcar_version':'0.1','structural_mapping':True,'core_verifier_physical_scope':False,
      'reason':'DDCAR v0.1 scope evaluator does not yet define physical-device authority constraints'}}
