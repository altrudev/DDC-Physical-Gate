import copy
import pytest

from physical_gate.core import keys, digest
from physical_gate.workflow_shadow import ShadowWorkflow, verify_workflow

def happy_commands():
    return [
      {'device':'reader','operation':'open_door','parameters':{}},
      {'device':'arm','operation':'move_plate_to_reader','parameters':{}},
      {'device':'reader','operation':'read','parameters':{}},
      {'device':'arm','operation':'return_plate','parameters':{}},
    ]

def test_cross_device_shadow_workflow_chain_verifies():
    sk,pub=keys()
    wf=ShadowWorkflow(sk)
    receipts=wf.run(happy_commands())
    report=wf.report()
    assert len(receipts)==4
    assert [r['payload']['sequence'] for r in receipts]==[1,2,3,4]
    assert all(r['payload']['decision']=='ALLOW' for r in receipts)
    assert all(r['payload']['simulation_status']=='SIMULATED' for r in receipts)
    assert all(r['payload']['hardware_write_capability'] is False for r in receipts)
    assert verify_workflow(report,{receipts[0]['key_id']:pub})==[]

def test_receipts_are_causally_linked():
    sk,pub=keys(); wf=ShadowWorkflow(sk); rs=wf.run(happy_commands())
    for i in range(1,len(rs)):
        assert rs[i]['payload']['parent_receipt_digest']==digest(rs[i-1])
        assert rs[i]['payload']['before_state_digest']==rs[i-1]['payload']['after_state_digest']
        assert rs[i]['payload']['before_generation']==rs[i-1]['payload']['after_generation']

def test_blocked_step_is_receipted_without_state_change():
    sk,pub=keys(); wf=ShadowWorkflow(sk)
    r=wf.evaluate_step({'device':'reader','operation':'read','parameters':{}})
    p=r['payload']
    assert p['decision']=='BLOCK'
    assert p['simulation_status']=='NOT_RUN'
    assert p['before_state_digest']==p['after_state_digest']
    assert p['before_generation']==p['after_generation']
    assert verify_workflow(wf.report(),{r['key_id']:pub})==[]

def test_tampered_command_breaks_verification():
    sk,pub=keys(); wf=ShadowWorkflow(sk); wf.run(happy_commands()); report=wf.report()
    report['receipts'][1]['payload']['command']['operation']='return_plate'
    errs=verify_workflow(report,{report['receipts'][0]['key_id']:pub})
    assert any('untrusted receipt 2' in e or 'command digest mismatch 2' in e for e in errs)

def test_parent_substitution_breaks_verification():
    sk,pub=keys(); wf=ShadowWorkflow(sk); wf.run(happy_commands()); report=wf.report()
    report['receipts'][2]['payload']['parent_receipt_digest']='deadbeef'
    errs=verify_workflow(report,{report['receipts'][0]['key_id']:pub})
    assert any('untrusted receipt 3' in e or 'parent mismatch 3' in e for e in errs)

def test_shadow_workflow_cannot_expose_dispatch():
    sk,pub=keys(); wf=ShadowWorkflow(sk); wf.run(happy_commands()); report=wf.report()
    report['dispatch']['permitted']=True
    assert 'dispatch capability exposed' in verify_workflow(report,{report['receipts'][0]['key_id']:pub})

def test_cross_device_ordering_failure_is_fail_closed():
    sk,pub=keys(); wf=ShadowWorkflow(sk)
    commands=[
      {'device':'arm','operation':'move_plate_to_reader','parameters':{}},
      {'device':'reader','operation':'read','parameters':{}},
    ]
    rs=wf.run(commands)
    assert rs[0]['payload']['decision']=='BLOCK'
    assert rs[1]['payload']['decision']=='BLOCK'
    assert rs[0]['payload']['simulation_status']=='NOT_RUN'
    assert rs[1]['payload']['simulation_status']=='NOT_RUN'
    assert verify_workflow(wf.report(),{rs[0]['key_id']:pub})==[]
