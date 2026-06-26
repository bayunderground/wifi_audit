
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, auto
from heapq import heappush, heappop

class SchedulerEvent(Enum):
    DISCOVER=auto()
    CLIENTS_PRESENT=auto()
    CAPTURE_SUCCESS=auto()
    CAPTURE_TIMEOUT=auto()
    VERIFY_SUCCESS=auto()
    VERIFY_FAILED=auto()

@dataclass(order=True)
class QueueEntry:
    due: datetime
    bssid: str

class Scheduler:
    def __init__(self,state,revisit_interval:int=300):
        self.state=state
        self.revisit=timedelta(seconds=revisit_interval)
        self._queue=[]
        self.rebuild()

    def rebuild(self):
        self._queue.clear()
        now=datetime.utcnow()
        for bssid,t in self.state.targets.items():
            due=t.last_attempt+self.revisit if t.last_attempt else now
            heappush(self._queue,QueueEntry(due,bssid))

    def due_targets(self,now=None):
        now=now or datetime.utcnow()
        out=[]
        while self._queue and self._queue[0].due<=now:
            e=heappop(self._queue)
            out.append(self.state.targets[e.bssid])
        return out

    def transition(self,target,event):
        s=target.state.name
        if s=="DISCOVERED" and event==SchedulerEvent.CLIENTS_PRESENT:
            target.state=type(target.state).CAPTURING
        elif s=="DISCOVERED" and event==SchedulerEvent.CAPTURE_TIMEOUT:
            target.state=type(target.state).WAITING_FOR_CLIENT
        elif s=="CAPTURING" and event==SchedulerEvent.CAPTURE_SUCCESS:
            target.state=type(target.state).VERIFYING
        elif s=="VERIFYING" and event==SchedulerEvent.VERIFY_SUCCESS:
            target.state=type(target.state).READY_TO_CRACK
        elif s=="VERIFYING" and event==SchedulerEvent.VERIFY_FAILED:
            target.state=type(target.state).WAITING_FOR_CLIENT
        target.last_attempt=datetime.utcnow()
        target.attempts+=1
        heappush(self._queue,QueueEntry(target.last_attempt+self.revisit,target.ap.bssid))
