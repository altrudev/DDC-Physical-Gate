"""Multi-device, simulation-only workflow coordinator for v0.3."""
from copy import deepcopy

class WorkflowError(ValueError): pass

class LabWorld:
    def __init__(self):
        self.state={'plate_location':'deck','lid':'ON','reader_busy':False,'arm_holding':None,
          'liquid_handler_busy':False,'reader_door':'CLOSED','sample_mixed':False,'bubbles_detected':False,
          'generation':1}
    def snapshot(self): return deepcopy(self.state)
    def _bump(self): self.state['generation']+=1

class WorkflowGate:
    """Cross-device causal/sequence constraints. No hardware transports."""
    def evaluate(self,world,command):
        s=world.snapshot(); dev=command.get('device'); op=command.get('operation'); p=command.get('parameters',{})
        findings=[]
        def block(code): findings.append(code)
        if dev not in ('arm','liquid-handler','reader'): block('UNKNOWN_DEVICE')
        if dev=='arm' and op=='move_plate_to_reader':
            if s['plate_location']!='deck' or s['arm_holding'] is not None: block('PLATE_NOT_AVAILABLE')
            if s['reader_busy'] or s['reader_door']!='OPEN': block('READER_NOT_READY')
        elif dev=='liquid-handler' and op=='mix':
            if s['plate_location']!='deck': block('PLATE_NOT_ON_DECK')
            if s['lid']!='OFF': block('LID_ON')
            if s['liquid_handler_busy']: block('LIQUID_HANDLER_BUSY')
            if p.get('cycles',0)>3: block('EXCESSIVE_MIXING')
            if s['bubbles_detected'] and p.get('reuse_same_well',False): block('BUBBLE_RETRY_HAZARD')
        elif dev=='reader' and op=='open_door':
            if s['reader_busy']: block('READER_BUSY')
            if s['plate_location']=='reader': block('PLATE_IN_READER')
        elif dev=='reader' and op=='read':
            if s['plate_location']!='reader': block('PLATE_NOT_IN_READER')
            if s['reader_door']!='CLOSED': block('READER_DOOR_OPEN')
            if s['reader_busy']: block('READER_BUSY')
        elif dev=='arm' and op=='return_plate':
            if s['plate_location']!='reader' or s['reader_busy']: block('PLATE_NOT_RETURNABLE')
        else:
            block('UNSUPPORTED_OPERATION')
        return {'disposition':'BLOCK' if findings else 'ALLOW','findings':findings,'generation':s['generation']}

class LabSimulator:
    def __init__(self): self.world=LabWorld(); self.gate=WorkflowGate()
    def execute(self,command):
        verdict=self.gate.evaluate(self.world,command)
        if verdict['disposition']!='ALLOW': raise WorkflowError(','.join(verdict['findings']))
        s=self.world.state; dev=command['device']; op=command['operation']; p=command.get('parameters',{})
        if dev=='reader' and op=='open_door': s['reader_door']='OPEN'
        elif dev=='arm' and op=='move_plate_to_reader': s['plate_location']='reader'; s['reader_door']='CLOSED'
        elif dev=='reader' and op=='read': s['reader_busy']=False
        elif dev=='arm' and op=='return_plate': s['plate_location']='deck'
        elif dev=='liquid-handler' and op=='mix':
            s['sample_mixed']=True
            if p.get('cycles',0)>=3: s['bubbles_detected']=True
        self.world._bump(); return self.world.snapshot()
