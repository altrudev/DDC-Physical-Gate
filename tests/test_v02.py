import copy, hashlib
import pytest
from physical_gate.core import fixture, digest, keys, PROFILE
from physical_gate.trust import sign_authority, sign_state
from physical_gate.secure_gate import SecureGate
from physical_gate.adapters import from_mcp, from_mhs, AdapterError
from physical_gate.ddcar import make_unsealed_receipt, construction_inputs, DDCAR_PHYSICAL_SCOPE_MIN_REVISION

NOW=1000000

def trusted_case():
    env,snap=fixture(NOW)
    ak,apub=keys(); sk,spub=keys()
    atrust={hashlib.sha256(bytes.fromhex(apub)).hexdigest():apub}
    strust={hashlib.sha256(bytes.fromhex(spub)).hexdigest():spub}
    agrant=sign_authority(ak,principal='human:owner',agent=env['agent'],device=env['device'],
        operations=PROFILE['operations'],action_digest=digest(env['action']),issued_ms=NOW-1,
        expires_ms=NOW+1000,nonce=env['nonce'],profile_digest=env['profile_digest'])
    satt=sign_state(sk,snap,valid_until_ms=NOW+500,source='simulator:arm-01')
    return env,snap,agrant,satt,atrust,strust

def test_secure_gate_allows_valid_signed_evidence():
    e,s,a,st,at,stt=trusted_case()
    r=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    assert r['disposition']=='ALLOW'
    assert r['trust_profile']=='cryptographic-v0.2'

@pytest.mark.parametrize('which',['authority','state'])
def test_secure_gate_blocks_untrusted_signatures(which):
    e,s,a,st,at,stt=trusted_case()
    other,opub=keys()
    if which=='authority': at={hashlib.sha256(bytes.fromhex(opub)).hexdigest():opub}
    else: stt={hashlib.sha256(bytes.fromhex(opub)).hexdigest():opub}
    r=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    assert r['disposition']=='BLOCK'

def test_authority_is_bound_to_exact_action():
    e,s,a,st,at,stt=trusted_case()
    e['action']['parameters']['speed']['value']=21
    e['snapshot_digest']=digest(s)
    r=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    assert r['disposition']=='BLOCK'
    assert any(x['code']=='AUTHORITY_ACTION' for x in r['findings'])

def test_authority_is_bound_to_nonce():
    e,s,a,st,at,stt=trusted_case()
    e['nonce']='different-nonce-123456789'
    r=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    assert r['disposition']=='BLOCK'
    assert any(x['code']=='AUTHORITY_NONCE' for x in r['findings'])

def test_expired_authority_blocks():
    e,s,a,st,at,stt=trusted_case()
    a['payload']['expires_ms']=NOW
    r=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    assert r['disposition']=='BLOCK'

def test_state_attestation_is_bound_to_snapshot():
    e,s,a,st,at,stt=trusted_case()
    s['generation']=2
    e['generation']=2
    e['snapshot_digest']=digest(s)
    e['trajectory_evidence']['snapshot_digest']=digest(s)
    r=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    assert r['disposition']=='BLOCK'
    assert any(x['code']=='STATE_ATTESTATION_DIGEST' for x in r['findings'])

def test_expired_state_attestation_blocks():
    e,s,a,st,at,stt=trusted_case()
    st['payload']['valid_until_ms']=NOW
    r=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    assert r['disposition']=='BLOCK'

def mcp_request(env):
    return {'protocol':'mcp-sim-v0','request_id':env['id'],'nonce':env['nonce'],'agent':env['agent'],
      'device':env['device'],'issued_ms':env['issued_ms'],'expires_ms':env['expires_ms'],'generation':env['generation'],
      'authority':copy.deepcopy(env['authority']),'consequence':env['consequence'],'reversible':env['reversible'],
      'tool_call':{'name':'arm.move','arguments':copy.deepcopy(env['action']['parameters'])},
      'trajectory_evidence':copy.deepcopy(env['trajectory_evidence'])}

def test_mcp_adapter_preserves_exact_action():
    e,s=fixture(NOW); x=from_mcp(mcp_request(e),s,PROFILE)
    assert x['action']==e['action']
    assert x['snapshot_digest']==digest(s)

def test_mcp_adapter_rejects_unknown_tool():
    e,s=fixture(NOW); r=mcp_request(e); r['tool_call']['name']='arm.override'
    with pytest.raises(AdapterError): from_mcp(r,s,PROFILE)

def test_mhs_research_adapter_preserves_exact_action():
    e,s=fixture(NOW)
    req={'protocol':'mhs-research-sim-v0','request_id':e['id'],'nonce':e['nonce'],'agent':e['agent'],
      'device':e['device'],'issued_ms':e['issued_ms'],'expires_ms':e['expires_ms'],'generation':e['generation'],
      'authority':copy.deepcopy(e['authority']),'consequence':e['consequence'],'reversible':e['reversible'],
      'command':copy.deepcopy(e['action']),'trajectory_evidence':copy.deepcopy(e['trajectory_evidence'])}
    x=from_mhs(req,s,PROFILE)
    assert x['action']==e['action']

def test_mhs_adapter_is_explicitly_not_official_schema():
    e,s=fixture(NOW)
    req={'protocol':'mhs-v1','request_id':e['id']}
    with pytest.raises(AdapterError): from_mhs(req,s,PROFILE)

def test_ddcar_construction_inputs_target_physical_scope_verifier():
    e,s,a,st,at,stt=trusted_case()
    d=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    mapped=construction_inputs(envelope=e,decision=d,state_signed=st,profile=PROFILE)
    r=mapped['receipt']
    assert mapped['interop']['physical_scope_supported'] is True
    assert mapped['interop']['minimum_verifier_revision']==DDCAR_PHYSICAL_SCOPE_MIN_REVISION
    assert mapped['interop']['requires_ddcar_signing'] is True
    assert r['decision']=='ALLOW'
    assert r['operation']=='move'
    assert r['evidence'][0]['type']=='physical-state'
    assert r['authority']['scope']['tool_id']==e['device']
    assert r['authority']['scope']['frame']=='sim-base'
    assert r['authority']['scope']['max_speed']==str(PROFILE['max_speed_mm_s'])

def test_ddcar_review_mapping():
    e,s,a,st,at,stt=trusted_case()
    e['consequence']=4
    d=SecureGate(authority_trust=at,state_trust=stt).evaluate(e,s,NOW,authority_proof=a,state_proof=st)
    mapped=make_unsealed_receipt(envelope=e,decision=d,authority_signed=a,state_signed=st)
    assert mapped['receipt']['decision']=='HUMAN-REVIEW'

def test_missing_crypto_proofs_fail_closed():
    e,s=fixture(NOW)
    r=SecureGate().evaluate(e,s,NOW)
    assert r['disposition']=='BLOCK'
    codes={x['code'] for x in r['findings']}
    assert 'AUTHORITY_SIGNATURE' in codes and 'STATE_SIGNATURE' in codes
