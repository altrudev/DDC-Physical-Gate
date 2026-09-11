"""Persistent monotonic state-lineage ledger for v0.4 simulation assurance."""
import sqlite3
from .core import digest

class StateLineageLedger:
    def __init__(self,path):
        self.db=sqlite3.connect(path,isolation_level=None)
        self.db.execute('CREATE TABLE IF NOT EXISTS state_lineage (device TEXT PRIMARY KEY, epoch TEXT NOT NULL, generation INTEGER NOT NULL, snapshot_digest TEXT NOT NULL)')
    def current(self,device):
        row=self.db.execute('SELECT epoch,generation,snapshot_digest FROM state_lineage WHERE device=?',(device,)).fetchone()
        return None if row is None else {'device_epoch':row[0],'generation':row[1],'snapshot_digest':row[2]}
    def check(self,attestation):
        a=attestation.get('payload',{})
        cur=self.current(a.get('device'))
        if cur is None:
            if a.get('generation') != 1: return False,'STATE_LINEAGE_INITIAL_GENERATION'
            if a.get('predecessor_state_digest') not in (None,''): return False,'STATE_LINEAGE_INITIAL_PREDECESSOR'
            return True,None
        if a.get('device_epoch')!=cur['device_epoch']: return False,'STATE_LINEAGE_EPOCH'
        if a.get('generation')<=cur['generation']: return False,'STATE_ROLLBACK'
        if a.get('generation')!=cur['generation']+1: return False,'STATE_LINEAGE_GAP'
        if a.get('predecessor_state_digest')!=cur['snapshot_digest']: return False,'STATE_LINEAGE_PREDECESSOR'
        return True,None
    def accept(self,attestation):
        ok,code=self.check(attestation)
        if not ok: return False,code
        a=attestation['payload']
        self.db.execute('INSERT INTO state_lineage(device,epoch,generation,snapshot_digest) VALUES (?,?,?,?) ON CONFLICT(device) DO UPDATE SET epoch=excluded.epoch,generation=excluded.generation,snapshot_digest=excluded.snapshot_digest',
          (a['device'],a['device_epoch'],a['generation'],a['snapshot_digest']))
        return True,None
    def close(self): self.db.close()
