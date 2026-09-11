import json, hashlib
from pathlib import Path
import pytest
from physical_gate.core import keys, PROFILE
from physical_gate.interop import deterministic_snapshot, deterministic_envelope, build_vector
from physical_gate.ddcar import action, physical_scope
from physical_gate.multi_device import LabSimulator, WorkflowError

ROOT=Path(__file__).resolve().parents[1]

def test_shared_ddcar_vector_exact_match():
    v=json.loads((ROOT/'conformance/ddcar-physical-v0.3.json').read_text())
    snap=deterministic_snapshot(); env=deterministic_envelope(snap)
    assert v['profile_digest']==env['profile_digest']
    assert v['snapshot_digest']==env['snapshot_digest']
    assert v['action']==action(env)
    assert v['scope']==physical_scope(env,PROFILE)
    assert v['agent']==env['agent'] and v['device']==env['device'] and v['nonce']==env['nonce']

def test_multi_device_happy_path():
    sim=LabSimulator()
    sim.execute({'device':'reader','operation':'open_door','parameters':{}})
    sim.execute({'device':'arm','operation':'move_plate_to_reader','parameters':{}})
    sim.execute({'device':'reader','operation':'read','parameters':{}})
    sim.execute({'device':'arm','operation':'return_plate','parameters':{}})
    assert sim.world.state['plate_location']=='deck'
    assert sim.world.state['generation']==5

@pytest.mark.parametrize('command,code',[
    ({'device':'arm','operation':'move_plate_to_reader','parameters':{}},'READER_NOT_READY'),
    ({'device':'liquid-handler','operation':'mix','parameters':{'cycles':1}},'LID_ON'),
    ({'device':'reader','operation':'read','parameters':{}},'PLATE_NOT_IN_READER'),
])
def test_multi_device_prerequisites_block(command,code):
    sim=LabSimulator()
    with pytest.raises(WorkflowError,match=code): sim.execute(command)

def test_bubble_retry_hazard_blocks_repeating_same_well():
    sim=LabSimulator(); sim.world.state['lid']='OFF'
    sim.execute({'device':'liquid-handler','operation':'mix','parameters':{'cycles':3,'reuse_same_well':False}})
    assert sim.world.state['bubbles_detected'] is True
    with pytest.raises(WorkflowError,match='BUBBLE_RETRY_HAZARD'):
        sim.execute({'device':'liquid-handler','operation':'mix','parameters':{'cycles':1,'reuse_same_well':True}})

def test_resource_conflict_blocks_arm_transfer():
    sim=LabSimulator(); sim.world.state['reader_door']='OPEN'; sim.world.state['reader_busy']=True
    with pytest.raises(WorkflowError,match='READER_NOT_READY'):
        sim.execute({'device':'arm','operation':'move_plate_to_reader','parameters':{}})

def test_unknown_cross_device_operation_fails_closed():
    sim=LabSimulator()
    with pytest.raises(WorkflowError,match='UNSUPPORTED_OPERATION'):
        sim.execute({'device':'reader','operation':'disable_interlock','parameters':{}})


def test_physical_gate_builds_allowing_ddcar_vector():
    import hashlib
    ak,apub=keys(); sk,spub=keys()
    atrust={hashlib.sha256(bytes.fromhex(apub)).hexdigest():apub}
    strust={hashlib.sha256(bytes.fromhex(spub)).hexdigest():spub}
    built=build_vector(ak,sk,atrust,strust)
    assert built['decision']['disposition']=='ALLOW'
    assert built['ddcar']['receipt']['decision']=='ALLOW'
    assert built['ddcar']['receipt']['operation']=='move'
    assert built['ddcar']['authority_grant']['action_digest'].startswith('sha256:')
