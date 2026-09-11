"""Cryptographic trust objects for the v0.2 simulation profile."""
import hashlib
from .core import sign, verify, digest

AUTHORITY_VERSION='ddc.physical-authority.v0.2'
STATE_VERSION='ddc.physical-state-attestation.v0.2'

def key_id_from_public_hex(public_hex):
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()

def authority_grant(*,principal,agent,device,operations,action_digest,issued_ms,expires_ms,nonce,profile_digest):
    return {'version':AUTHORITY_VERSION,'principal':principal,'agent':agent,'device':device,
            'operations':list(operations),'action_digest':action_digest,'issued_ms':issued_ms,
            'expires_ms':expires_ms,'nonce':nonce,'profile_digest':profile_digest}

def sign_authority(private_key, **kwargs):
    return sign(private_key, authority_grant(**kwargs))

def verify_authority(signed, trusted, *, envelope, now_ms):
    if not verify(signed,trusted): return False,'AUTHORITY_SIGNATURE'
    g=signed.get('payload',{})
    if g.get('version')!=AUTHORITY_VERSION: return False,'AUTHORITY_VERSION'
    if g.get('agent')!=envelope.get('agent') or g.get('device')!=envelope.get('device'): return False,'AUTHORITY_BINDING'
    if envelope.get('action',{}).get('operation') not in g.get('operations',[]): return False,'AUTHORITY_OPERATION'
    if g.get('action_digest')!=digest(envelope.get('action')): return False,'AUTHORITY_ACTION'
    if g.get('profile_digest')!=envelope.get('profile_digest'): return False,'AUTHORITY_PROFILE'
    if g.get('nonce')!=envelope.get('nonce'): return False,'AUTHORITY_NONCE'
    try:
        if g.get('issued_ms')>now_ms or g.get('expires_ms')<=now_ms: return False,'AUTHORITY_TIME'
    except TypeError: return False,'AUTHORITY_TIME'
    return True,None

def state_attestation(*,snapshot_digest,device,generation,observed_ms,valid_until_ms,profile_digest,source):
    return {'version':STATE_VERSION,'snapshot_digest':snapshot_digest,'device':device,'generation':generation,
            'observed_ms':observed_ms,'valid_until_ms':valid_until_ms,'profile_digest':profile_digest,'source':source}

def sign_state(private_key, snapshot, *, valid_until_ms, source):
    return sign(private_key,state_attestation(snapshot_digest=digest(snapshot),device=snapshot['device'],
        generation=snapshot['generation'],observed_ms=snapshot['observed_ms'],valid_until_ms=valid_until_ms,
        profile_digest=snapshot['profile_digest'],source=source))

def verify_state(signed,trusted,*,snapshot,now_ms):
    if not verify(signed,trusted): return False,'STATE_SIGNATURE'
    a=signed.get('payload',{})
    if a.get('version')!=STATE_VERSION: return False,'STATE_ATTESTATION_VERSION'
    if a.get('snapshot_digest')!=digest(snapshot): return False,'STATE_ATTESTATION_DIGEST'
    if a.get('device')!=snapshot.get('device') or a.get('generation')!=snapshot.get('generation'): return False,'STATE_ATTESTATION_BINDING'
    if a.get('profile_digest')!=snapshot.get('profile_digest'): return False,'STATE_ATTESTATION_PROFILE'
    try:
        if a.get('observed_ms')!=snapshot.get('observed_ms') or a.get('valid_until_ms')<=now_ms: return False,'STATE_ATTESTATION_TIME'
    except TypeError: return False,'STATE_ATTESTATION_TIME'
    return True,None
