import copy, hashlib
import pytest

from physical_gate.core import PROFILE, digest, keys, fixture
from physical_gate.trust import sign_authority, sign_state
from physical_gate.shadow import MCPShadowBoundary, ShadowModeError, assert_shadow_only

NOW=1000000

def setup():
    env,snap=fixture(NOW)
    dk,dpub=keys(); ak,apub=keys(); sk,spub=keys()
    authority=sign_authority(ak,principal='human:owner',agent=env['agent'],device=env['device'],
      operations=PROFILE['operations'],action_digest=digest(env['action']),issued_ms=NOW-1,
      expires_ms=NOW+1000,nonce=env['nonce'],profile_digest=env['profile_digest'])
    state=sign_state(sk,snap,valid_until_ms=NOW+500,source='simulator:arm-01')
    boundary=MCPShadowBoundary(decision_signer=dk,
      authority_trust={authority['key_id']:apub},state_trust={state['key_id']:spub})
    req={'protocol':'mcp-sim-v0','request_id':env['id'],'nonce':env['nonce'],'agent':env['agent'],
      'device':env['device'],'issued_ms':env['issued_ms'],'expires_ms':env['expires_ms'],
      'generation':env['generation'],'authority':copy.deepcopy(env['authority']),
      'consequence':env['consequence'],'reversible':env['reversible'],
      'tool_call':{'name':'arm.move','arguments':copy.deepcopy(env['action']['parameters'])},
      'trajectory_evidence':copy.deepcopy(env['trajectory_evidence'])}
    return env,snap,authority,state,boundary,req

def test_shadow_allow_never_exposes_dispatch():
    env,snap,a,s,b,req=setup()
    out=b.evaluate(req,snap,NOW,authority_proof=a,state_proof=s)
    assert out['decision']=='ALLOW'
    assert out['dispatch']=={'available':False,'permitted':False,'reason':'shadow-mode-no-transport'}
    assert out['hardware_write_capability'] is False
    assert assert_shadow_only(out) is True
    assert out['ddcar_preview']['receipt']['decision']=='ALLOW'

def test_shadow_blocks_stale_telemetry():
    env,snap,a,s,b,req=setup()
    stale=copy.deepcopy(snap)
    stale['observed_ms']=NOW-1000
    for sensor in stale['sensors'].values(): sensor['observed_ms']=NOW-1000
    req['generation']=stale['generation']
    s2_key,s2_pub=keys()
    state=sign_state(s2_key,stale,valid_until_ms=NOW+500,source='simulator:arm-01')
    b=MCPShadowBoundary(decision_signer=keys()[0],
      authority_trust={a['key_id']:a and b.gate.authority_trust[a['key_id']]},
      state_trust={state['key_id']:s2_pub})
    # authority proof is still bound to the same exact action/envelope fields.
    out=b.evaluate(req,stale,NOW,authority_proof=a,state_proof=state)
    assert out['decision']=='BLOCK'
    assert any(f['code']=='STALE_STATE' for f in out['findings'])

def test_shadow_rejects_unknown_mcp_tool():
    env,snap,a,s,b,req=setup()
    req['tool_call']['name']='arm.disable_interlock'
    with pytest.raises(ShadowModeError,match='unsupported tool'):
        b.evaluate(req,snap,NOW,authority_proof=a,state_proof=s)

def test_shadow_revoked_authority_blocks():
    env,snap,a,s,b,req=setup()
    revoked={digest(a['payload'])}
    b=MCPShadowBoundary(decision_signer=keys()[0],
      authority_trust=b.gate.authority_trust,state_trust=b.gate.state_trust,
      authority_revocations=revoked)
    out=b.evaluate(req,snap,NOW,authority_proof=a,state_proof=s)
    assert out['decision']=='BLOCK'
    assert any(f['code']=='AUTHORITY_REVOKED' for f in out['findings'])
    assert assert_shadow_only(out)

def test_shadow_tampered_state_proof_blocks():
    env,snap,a,s,b,req=setup()
    tampered=copy.deepcopy(s); tampered['payload']['generation']=99
    out=b.evaluate(req,snap,NOW,authority_proof=a,state_proof=tampered)
    assert out['decision']=='BLOCK'
    assert any(f['code']=='STATE_SIGNATURE' for f in out['findings'])

def test_assert_shadow_only_rejects_capability_flip():
    env,snap,a,s,b,req=setup()
    out=b.evaluate(req,snap,NOW,authority_proof=a,state_proof=s)
    out['dispatch']['permitted']=True
    with pytest.raises(ShadowModeError,match='dispatch capability'):
        assert_shadow_only(out)
