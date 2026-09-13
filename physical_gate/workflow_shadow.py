"""Cross-device shadow workflow receipts for v0.4.

This module is simulation-only. It links each proposed/observed workflow step to the
previous signed receipt and simulated world-state transition. It has no hardware
transport and makes no claim that the arm-specific DDCAR scope covers other devices.
"""
from copy import deepcopy

from .core import canonical, digest, sign, verify
from .multi_device import LabSimulator, WorkflowError

WORKFLOW_SCHEMA='ddc.physical-workflow-shadow/0.4'
RECEIPT_SCHEMA='ddc.physical-workflow-receipt/0.4'

class WorkflowReceiptError(ValueError):
    pass

class ShadowWorkflow:
    def __init__(self, signer):
        self.signer=signer
        self.sim=LabSimulator()
        self.receipts=[]

    def _parent_digest(self):
        return None if not self.receipts else digest(self.receipts[-1])

    def evaluate_step(self, command):
        before=self.sim.world.snapshot()
        verdict=self.sim.gate.evaluate(self.sim.world,command)
        base={
          'schema':RECEIPT_SCHEMA,
          'mode':'SHADOW',
          'sequence':len(self.receipts)+1,
          'parent_receipt_digest':self._parent_digest(),
          'command':deepcopy(command),
          'command_digest':digest(command),
          'before_state_digest':digest(before),
          'before_generation':before['generation'],
          'decision':verdict['disposition'],
          'findings':list(verdict['findings']),
          'dispatch':{'available':False,'permitted':False,'reason':'shadow-workflow-no-transport'},
          'hardware_write_capability':False,
        }
        if verdict['disposition']=='ALLOW':
            # Advance only the in-memory simulator so later shadow steps are checked
            # against the causally resulting simulated state. No physical transport exists.
            after=self.sim.execute(deepcopy(command))
            base.update({
              'simulation_status':'SIMULATED',
              'after_state_digest':digest(after),
              'after_generation':after['generation'],
            })
        else:
            base.update({
              'simulation_status':'NOT_RUN',
              'after_state_digest':digest(before),
              'after_generation':before['generation'],
            })
        signed=sign(self.signer,base)
        self.receipts.append(signed)
        return signed

    def run(self, commands):
        return [self.evaluate_step(c) for c in commands]

    def report(self):
        return {
          'schema':WORKFLOW_SCHEMA,
          'mode':'SHADOW',
          'receipt_count':len(self.receipts),
          'head_receipt_digest':self._parent_digest(),
          'receipts':deepcopy(self.receipts),
          'dispatch':{'available':False,'permitted':False,'reason':'shadow-workflow-no-transport'},
          'hardware_write_capability':False,
        }

def verify_workflow(report, trusted):
    errors=[]
    if report.get('schema')!=WORKFLOW_SCHEMA or report.get('mode')!='SHADOW':
        return ['invalid workflow schema/mode']
    if report.get('hardware_write_capability') is not False:
        errors.append('hardware write capability exposed')
    d=report.get('dispatch',{})
    if d.get('available') or d.get('permitted'):
        errors.append('dispatch capability exposed')
    receipts=report.get('receipts',[])
    previous=None
    previous_after=None
    previous_generation=None
    for i,signed in enumerate(receipts,1):
        if not verify(signed,trusted):
            errors.append(f'untrusted receipt {i}')
            continue
        r=signed.get('payload',{})
        if r.get('schema')!=RECEIPT_SCHEMA or r.get('mode')!='SHADOW':
            errors.append(f'invalid receipt schema/mode {i}')
        if r.get('sequence')!=i:
            errors.append(f'sequence mismatch {i}')
        expected=None if previous is None else digest(previous)
        if r.get('parent_receipt_digest')!=expected:
            errors.append(f'parent mismatch {i}')
        if r.get('command_digest')!=digest(r.get('command')):
            errors.append(f'command digest mismatch {i}')
        if r.get('hardware_write_capability') is not False:
            errors.append(f'hardware capability exposed {i}')
        rd=r.get('dispatch',{})
        if rd.get('available') or rd.get('permitted'):
            errors.append(f'dispatch capability exposed {i}')
        if previous_after is not None and r.get('before_state_digest')!=previous_after:
            errors.append(f'state lineage mismatch {i}')
        if previous_generation is not None and r.get('before_generation')!=previous_generation:
            errors.append(f'generation lineage mismatch {i}')
        if r.get('decision')=='ALLOW':
            if r.get('simulation_status')!='SIMULATED':
                errors.append(f'allowed step not simulated {i}')
            if r.get('after_generation')!=r.get('before_generation')+1:
                errors.append(f'generation did not advance {i}')
        else:
            if r.get('simulation_status')!='NOT_RUN':
                errors.append(f'blocked step simulated {i}')
            if r.get('after_generation')!=r.get('before_generation'):
                errors.append(f'blocked step changed generation {i}')
        previous=signed
        previous_after=r.get('after_state_digest')
        previous_generation=r.get('after_generation')
    if receipts:
        if report.get('head_receipt_digest')!=digest(receipts[-1]):
            errors.append('head receipt mismatch')
    elif report.get('head_receipt_digest') is not None:
        errors.append('nonempty head for empty workflow')
    return errors
