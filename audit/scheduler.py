from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from heapq import heappush, heappop
from .models import AuditState, AuditTarget, APState
from .logging import get_logger

log = get_logger(__name__)

class SchedulerEvent(Enum):
    DISCOVER = auto()
    CLIENTS_PRESENT = auto()
    CAPTURE_SUCCESS = auto()
    CAPTURE_TIMEOUT = auto()
    VERIFY_SUCCESS = auto()
    VERIFY_FAILED = auto()

@dataclass(order=True)
class QueueEntry:
    due: datetime
    bssid: str

class Scheduler:
    def __init__(self, state: AuditState, revisit_interval: int = 300):
        self.state = state
        self.revisit = timedelta(seconds=revisit_interval)
        self._queue: list[QueueEntry] = []
        self.rebuild()

    def rebuild(self) -> None:
        self._queue.clear()
        now = datetime.now(timezone.utc)
        for bssid, t in self.state.targets.items():
            due = t.last_attempt + self.revisit if t.last_attempt else now
            heappush(self._queue, QueueEntry(due, bssid))

    _ACTIVE_STATES = {APState.CAPTURING, APState.VERIFYING, APState.READY_TO_CRACK}

    def due_targets(self, now: datetime | None = None) -> list[AuditTarget]:
        now = now or datetime.now(timezone.utc)
        out: list[AuditTarget] = []
        seen: set[str] = set()
        # Always include targets in active states (need immediate processing)
        for t in self.state.targets.values():
            if t.state in self._ACTIVE_STATES:
                out.append(t)
                seen.add(t.ap.bssid)
        # Peek at due queue entries without popping — DISCOVERED targets
        # stay queued until they actually transition state
        for e in self._queue:
            if e.due > now:
                break
            if e.bssid not in seen:
                target = self.state.targets[e.bssid]
                if target.state == APState.DISCOVERED:
                    out.append(target)
                    seen.add(e.bssid)
        return out

    def transition(self, target: AuditTarget, event: SchedulerEvent) -> None:
        s = target.state.name
        if s == "DISCOVERED" and event == SchedulerEvent.CLIENTS_PRESENT:
            target.state = type(target.state).CAPTURING
        elif s == "DISCOVERED" and event == SchedulerEvent.CAPTURE_TIMEOUT:
            target.state = type(target.state).WAITING_FOR_CLIENT
        elif s == "CAPTURING" and event == SchedulerEvent.CAPTURE_SUCCESS:
            target.state = type(target.state).VERIFYING
        elif s == "CAPTURING" and event == SchedulerEvent.CAPTURE_TIMEOUT:
            target.state = type(target.state).WAITING_FOR_CLIENT
        elif s == "VERIFYING" and event == SchedulerEvent.VERIFY_SUCCESS:
            target.state = type(target.state).READY_TO_CRACK
        elif s == "VERIFYING" and event == SchedulerEvent.VERIFY_FAILED:
            target.state = type(target.state).WAITING_FOR_CLIENT
        else:
            log.warning("Invalid transition: %s + %s", s, event.name)
            return
        target.last_attempt = datetime.now(timezone.utc)
        target.attempts += 1
        heappush(self._queue, QueueEntry(target.last_attempt + self.revisit, target.ap.bssid))
