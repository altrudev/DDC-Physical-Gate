"""Deterministic v0.3 conformance vector for cross-repo DDCAR verification."""
from copy import deepcopy
from .core import PROFILE, VERSION, digest
from .ddcar import construction_inputs
from .secure_gate import SecureGate
from .trust import sign_authority, sign_state

VECTOR_NOW=1_000_000

def deterministic_envelope(snapshot):
    action={'operation':'move','parameters':{
      'target':{
        'x':{'value':'10','unit':'mm','frame':'sim-base','uncertainty_mm':'0'},
        'y':{'value':'20','unit':'mm','frame':'sim-base','uncertainty_mm':'0'},
        'z':{'value':'100','unit':'mm','frame':'sim-base','uncertainty_mm':'0'}},
      'speed':{'value':'20','unit':'mm/s'},'force':{'value':'5','unit':'N'}}}
    env={'version':VERSION,'id':'physical-v03-vector-0001','nonce':'0123456789abcdef0123456789abcdef',
      'agent':'sim:agent','device':PROFILE['device'],'issued_ms':VECTOR_NOW-1,'expires_ms':VECTOR_NOW+1000,
      'generation':snapshot['generation'],'profile_digest':digest(PROFILE),'snapshot_digest':digest(snapshot),
      'action':action,'authority':{'verified':True,'agent':'sim:agent','device':PROFILE['device'],
        'operations':PROFILE['operations'],'expires_ms':VECTOR_NOW+1000},'consequence':1,'reversible':True,
      'trajectory_evidence':{'valid':True,'profile_digest':digest(PROFILE),'snapshot_digest':digest(snapshot)}}
    return env

def deterministic_snapshot():
    def s(v): return {'value':v,'valid':True,'observed_ms':VECTOR_NOW}
    sensors={k:s(v) for k,v in {'position':{'x':0,'y':0,'z':100},'guard_closed':True,'estop':False,
      'homed':True,'temperature_C':22,'battery_pct':80,'payload_kg':0.5,'force_N':0}.items()}
    return {'version':VERSION,'device':PROFILE['device'],'profile_digest':digest(PROFILE),'generation':1,
      'attested':True,'observed_ms':VECTOR_NOW,'clock_uncertainty_ms':1,'mode':'READY','fault':False,
      'interlock_latched':False,'active_resources':[],'retries':0,'gripper':'OPEN','object_present':False,
      'sensors':sensors,'cross_checks':[]}

def build_vector(authority_key,state_key,authority_trust,state_trust):
    snapshot=deterministic_snapshot(); envelope=deterministic_envelope(snapshot)
    authority=sign_authority(authority_key,principal='human:owner',agent=envelope['agent'],device=envelope['device'],
      operations=PROFILE['operations'],action_digest=digest(envelope['action']),issued_ms=VECTOR_NOW-2,
      expires_ms=VECTOR_NOW+1000,nonce=envelope['nonce'],profile_digest=envelope['profile_digest'])
    state=sign_state(state_key,snapshot,valid_until_ms=VECTOR_NOW+500,source='simulator:arm-01')
    decision=SecureGate(authority_trust=authority_trust,state_trust=state_trust).evaluate(
      envelope,snapshot,VECTOR_NOW,authority_proof=authority,state_proof=state)
    mapped=construction_inputs(envelope=envelope,decision=decision,state_signed=state,profile=PROFILE)
    return {'envelope':envelope,'snapshot':snapshot,'decision':decision,'ddcar':mapped}
