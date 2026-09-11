"""Simulation-only normalizers for MCP- and MHS-shaped requests. No transports."""
from copy import deepcopy
from .core import VERSION, digest

class AdapterError(ValueError): pass

def _base(req,snapshot,profile):
    for k in ('request_id','nonce','agent','device','issued_ms','expires_ms','generation','authority','consequence','reversible'):
        if k not in req: raise AdapterError('missing '+k)
    if req['device']!=profile['device']: raise AdapterError('device mismatch')
    return {'version':VERSION,'id':str(req['request_id']),'nonce':str(req['nonce']),'agent':str(req['agent']),
      'device':req['device'],'issued_ms':req['issued_ms'],'expires_ms':req['expires_ms'],'generation':req['generation'],
      'profile_digest':digest(profile),'snapshot_digest':digest(snapshot),'authority':deepcopy(req['authority']),
      'consequence':req['consequence'],'reversible':req['reversible']}

def from_mcp(req,snapshot,profile):
    if req.get('protocol')!='mcp-sim-v0': raise AdapterError('unsupported MCP profile')
    b=_base(req,snapshot,profile)
    call=req.get('tool_call',{})
    if set(call)!={'name','arguments'}: raise AdapterError('invalid tool call')
    name=call['name']
    if name=='arm.move':
        args=call['arguments']
        b['action']={'operation':'move','parameters':deepcopy(args)}
        b['trajectory_evidence']=deepcopy(req.get('trajectory_evidence',{}))
    elif name in ('arm.grip','arm.release','arm.home'):
        b['action']={'operation':name.split('.')[1],'parameters':deepcopy(call['arguments'])}
    else: raise AdapterError('unsupported tool')
    return b

def from_mhs(req,snapshot,profile):
    # Research-preview compatibility shape only; not an official Anthropic MHS schema.
    if req.get('protocol')!='mhs-research-sim-v0': raise AdapterError('unsupported MHS profile')
    b=_base(req,snapshot,profile)
    command=req.get('command',{})
    if set(command)!={'operation','parameters'}: raise AdapterError('invalid command')
    b['action']={'operation':command['operation'],'parameters':deepcopy(command['parameters'])}
    if b['action']['operation']=='move': b['trajectory_evidence']=deepcopy(req.get('trajectory_evidence',{}))
    return b
