import hashlib, json, math, time, uuid
from decimal import Decimal, InvalidOperation
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

VERSION = 'ddc.physical-gate.v0.1'

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def number(v):
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        raise ValueError('invalid numeric type')
    try:
        d = Decimal(str(v))
        if not d.is_finite(): raise ValueError('nonfinite')
        return d
    except InvalidOperation: raise ValueError('invalid number')

def keys():
    k = Ed25519PrivateKey.generate()
    return k, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

def sign(k, payload):
    return {'payload':payload, 'signature':k.sign(canonical(payload)).hex(), 'algorithm':'Ed25519', 'key_id':hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()}

def verify(signed, trusted):
    try:
        pub = bytes.fromhex(trusted[signed['key_id']])
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signed['signature']), canonical(signed['payload']))
        return True
    except (KeyError, ValueError, TypeError, Exception):
        return False

PROFILE = {'id':'sim-arm-v1', 'device':'sim:arm-01', 'operations':['move','grip','release','home'],
 'workspace_mm':{'x':[-500,500],'y':[-500,500],'z':[0,500]},
 'max_speed_mm_s':100,'max_force_N':20,'max_payload_kg':2,
 'max_observation_age_ms':500,'max_clock_uncertainty_ms':50,
 'max_uncertainty_mm':2,'max_temperature_C':40,'min_battery_pct':10,
 'max_retries':2,'review_force_N':10,'review_speed_mm_s':60,'review_consequence':3,
 'max_simulation_age_ms':1000,'max_permit_ms':1000}

class Gate:
    def __init__(self, profile=None):
        self.profile = profile or PROFILE

    def evaluate(self, envelope, snapshot, now_ms=None, simulation=None, history=None):
        now = int(time.time()*1000) if now_ms is None else now_ms
        p = self.profile
        findings=[]
        def add(code, level='BLOCK'):
            findings.append({'code':code,'disposition':level})
        if not isinstance(envelope,dict) or not isinstance(snapshot,dict):
            return {'disposition':'BLOCK','findings':[{'code':'MALFORMED','disposition':'BLOCK'}]}
        a=envelope.get('action',{}); op=a.get('operation'); params=a.get('parameters',{})
        if not isinstance(a,dict) or not isinstance(params,dict):
            return {'disposition':'BLOCK','findings':[{'code':'MALFORMED','disposition':'BLOCK'}]}
        try:
            digest(envelope); digest(snapshot)
        except (ValueError, TypeError, OverflowError):
            return {'disposition':'BLOCK','findings':[{'code':'NONCANONICAL_INPUT','disposition':'BLOCK'}]}
        required_envelope={'version','id','nonce','agent','device','issued_ms','expires_ms','generation','profile_digest','snapshot_digest','action','authority','consequence','reversible'}
        if not required_envelope.issubset(envelope) or not isinstance(envelope.get('id'),str) or not envelope.get('id') or not isinstance(envelope.get('agent'),str) or not envelope.get('agent'): add('ENVELOPE_SCHEMA')
        if envelope.get('version')!=VERSION or snapshot.get('version')!=VERSION: add('VERSION')
        if envelope.get('device')!=p['device'] or snapshot.get('device')!=p['device']: add('DEVICE_IDENTITY')
        if op not in p['operations']: add('CAPABILITY')
        if envelope.get('profile_digest')!=digest(p): add('PROFILE_MISMATCH')
        if envelope.get('snapshot_digest')!=digest(snapshot): add('SNAPSHOT_MISMATCH')
        try:
            if number(envelope.get('expires_ms'))<=now or number(envelope.get('issued_ms'))>now: add('COMMAND_TIME')
        except (ValueError,TypeError): add('COMMAND_TIME')
        if not isinstance(envelope.get('nonce'),str) or not envelope.get('nonce'): add('NONCE')
        grant=envelope.get('authority',{})
        if not isinstance(grant,dict): grant={}; add('AUTHORITY_SCHEMA')
        if not grant.get('verified') or grant.get('agent')!=envelope.get('agent') or grant.get('device')!=p['device'] or op not in grant.get('operations',[]) or grant.get('expires_ms',0)<=now: add('AUTHORITY')
        if not snapshot.get('attested',False): add('UNTRUSTED_STATE')
        if snapshot.get('profile_digest')!=digest(p): add('STATE_PROFILE')
        try:
            if number(snapshot.get('clock_uncertainty_ms'))<0 or number(snapshot.get('clock_uncertainty_ms'))>p['max_clock_uncertainty_ms']: add('CLOCK_UNCERTAINTY')
        except (ValueError,TypeError): add('CLOCK_UNCERTAINTY')
        try:
            if number(snapshot.get('observed_ms'))>now or now-number(snapshot.get('observed_ms'))>p['max_observation_age_ms']: add('STALE_STATE')
        except (ValueError,TypeError): add('STALE_STATE')
        if snapshot.get('generation')!=envelope.get('generation'): add('GENERATION')
        sensors=snapshot.get('sensors',{})
        if not isinstance(sensors,dict): sensors={}; add('SENSORS')
        required=['position','guard_closed','estop','homed','temperature_C','battery_pct','payload_kg','force_N']
        for name in required:
            s=sensors.get(name,{})
            if not isinstance(s,dict) or not s.get('valid') or s.get('observed_ms',now+1)>now or now-s.get('observed_ms',0)>p['max_observation_age_ms']:
                add('SENSOR_'+name.upper())
        def value(name, default=None): return sensors.get(name,{}).get('value',default)
        if value('estop') is not False or value('guard_closed') is not True: add('INTERLOCK')
        if value('homed') is not True and op not in ('home',): add('NOT_HOMED')
        try:
            if number(value('temperature_C'))>number(p['max_temperature_C']): add('TEMPERATURE')
            if number(value('battery_pct'))<number(p['min_battery_pct']): add('BATTERY')
            if number(value('payload_kg'))>number(p['max_payload_kg']): add('PAYLOAD')
            if number(value('force_N'))>number(p['max_force_N']): add('MEASURED_FORCE')
            for axis, bounds in p['workspace_mm'].items():
                if not bounds[0]<=number(value('position')[axis])<=bounds[1]: add('STATE_POSITION')
        except (ValueError, TypeError, KeyError): add('STATE_UNITS_OR_VALUES')
        for group in snapshot.get('cross_checks',[]):
            try:
                vals=[number(sensors[n]['value']) for n in group['sensors']]
                if max(vals)-min(vals)>number(group['tolerance']): add('SENSOR_CONFLICT')
            except (KeyError, ValueError, TypeError): add('CROSS_CHECK_INVALID')
        if snapshot.get('mode')!='READY' and op!='home': add('STATE_MACHINE')
        if snapshot.get('fault') or snapshot.get('interlock_latched'): add('LATCHED_FAULT')
        if snapshot.get('active_resources'): add('RESOURCE_CONFLICT')
        try:
            if number(snapshot.get('retries'))<0: add('RETRY_INVALID')
            elif number(snapshot.get('retries'))>p['max_retries']: add('RETRY_ANOMALY','REQUIRE HUMAN')
        except (ValueError,TypeError): add('RETRY_INVALID')
        if history and history.get('anomaly',False): add('RADIAL_ANOMALY','REQUIRE HUMAN')
        try:
            consequence=number(envelope['consequence'])
            if consequence<0: add('CONSEQUENCE_INVALID')
            elif consequence>=p['review_consequence']: add('CONSEQUENCE','REQUIRE HUMAN')
        except (KeyError,TypeError,ValueError): add('CONSEQUENCE_INVALID')
        if type(envelope.get('reversible')) is not bool: add('REVERSIBILITY_INVALID')
        elif envelope['reversible'] is False: add('IRREVERSIBLE','REQUIRE HUMAN')
        if envelope.get('uncertainty',{}).get('unresolved',False): add('UNCERTAINTY','REQUIRE HUMAN')
        if op=='move':
            if set(params)!={'target','speed','force'}: add('PARAMETER_SCHEMA')
            else:
                try:
                    target=params['target']
                    if set(target)!=set(p['workspace_mm']): add('COORDINATE_SCHEMA')
                    for axis,bounds in p['workspace_mm'].items():
                        v=target[axis]
                        if v.get('unit')!='mm' or v.get('frame')!='sim-base': add('COORDINATE_UNIT_FRAME')
                        u=number(v.get('uncertainty_mm',0))
                        if u<0 or u>p['max_uncertainty_mm']: add('POSITION_UNCERTAINTY')
                        x=number(v['value'])
                        if x-u<bounds[0] or x+u>bounds[1]: add('WORKSPACE')
                    for name,unit,limit in [('speed','mm/s','max_speed_mm_s'),('force','N','max_force_N')]:
                        v=params[name]
                        if v.get('unit')!=unit: add('UNIT_'+name.upper())
                        n=number(v['value'])
                        if n<0 or n>p[limit]: add('LIMIT_'+name.upper())
                    if number(params['speed']['value'])>p['review_speed_mm_s']: add('SPEED_REVIEW','REQUIRE HUMAN')
                    if number(params['force']['value'])>p['review_force_N']: add('FORCE_REVIEW','REQUIRE HUMAN')
                    if not envelope.get('trajectory_evidence',{}).get('valid'): add('TRAJECTORY_UNVERIFIED','SIMULATE FIRST')
                    elif envelope['trajectory_evidence'].get('profile_digest')!=digest(p) or envelope['trajectory_evidence'].get('snapshot_digest')!=digest(snapshot): add('TRAJECTORY_STALE','SIMULATE FIRST')
                except (KeyError,TypeError,ValueError,AttributeError): add('PARAMETER_INVALID')
        elif op in ('grip','release','home'):
            if params: add('PARAMETER_SCHEMA')
            if op=='grip' and (snapshot.get('gripper')!='OPEN' or not snapshot.get('object_present',False)): add('SEQUENCE')
            if op=='release' and snapshot.get('gripper')!='CLOSED': add('SEQUENCE')
            if op=='home' and snapshot.get('mode') not in ('READY','UNHOMED'): add('SEQUENCE')
        if 'instructions' in envelope or 'override' in envelope: add('UNTRUSTED_INSTRUCTION')
        if simulation is not None:
            if not simulation.get('valid') or simulation.get('action_digest')!=digest(a) or simulation.get('snapshot_digest')!=digest(snapshot) or simulation.get('profile_digest')!=digest(p) or now-simulation.get('completed_ms',0)>p['max_simulation_age_ms'] or simulation.get('completed_ms',now+1)>now: add('SIMULATION_INVALID','SIMULATE FIRST')
        levels={f['disposition'] for f in findings}
        disposition=next((d for d in ['BLOCK','REQUIRE HUMAN','SIMULATE FIRST'] if d in levels),'ALLOW')
        return {'disposition':disposition,'findings':findings,'action_digest':digest(a),'snapshot_digest':digest(snapshot),'profile_digest':digest(p),'evaluated_ms':now}

def fixture(now=1000000):
    p=PROFILE
    def s(v): return {'value':v,'valid':True,'observed_ms':now}
    sensors={k:s(v) for k,v in {'position':{'x':0,'y':0,'z':100},'guard_closed':True,'estop':False,'homed':True,'temperature_C':22,'battery_pct':80,'payload_kg':0.5,'force_N':0}.items()}
    snap={'version':VERSION,'device':p['device'],'profile_digest':digest(p),'generation':1,'attested':True,'observed_ms':now,'clock_uncertainty_ms':1,'mode':'READY','fault':False,'interlock_latched':False,'active_resources':[],'retries':0,'gripper':'OPEN','object_present':False,'sensors':sensors,'cross_checks':[]}
    action={'operation':'move','parameters':{'target':{k:{'value':v,'unit':'mm','frame':'sim-base','uncertainty_mm':0} for k,v in {'x':10,'y':20,'z':100}.items()},'speed':{'value':20,'unit':'mm/s'},'force':{'value':5,'unit':'N'}}}
    env={'version':VERSION,'id':str(uuid.uuid4()),'nonce':str(uuid.uuid4()),'agent':'sim:agent','device':p['device'],'issued_ms':now,'expires_ms':now+1000,'generation':1,'profile_digest':digest(p),'snapshot_digest':digest(snap),'action':action,'authority':{'verified':True,'agent':'sim:agent','device':p['device'],'operations':p['operations'],'expires_ms':now+1000},'consequence':1,'reversible':True,'trajectory_evidence':{'valid':True,'profile_digest':digest(p),'snapshot_digest':digest(snap)}}
    return env,snap
