from datetime import datetime,timedelta,timezone
from audit.scheduler import Scheduler,SchedulerEvent
from audit.models import AccessPoint,AuditTarget,AuditState,APState

def test_scheduler_transitions():
    ap=AccessPoint("TP-Link_Test","aa",1,-40,"WPA2")
    t=AuditTarget(ap=ap,state=APState.DISCOVERED)
    st=AuditState(targets={"aa":t})
    sch=Scheduler(st,10)

    now=datetime.now(timezone.utc)
    assert len(sch.due_targets(now))==1
    sch.transition(t,SchedulerEvent.CLIENTS_PRESENT)
    assert t.state==APState.CAPTURING
    sch.transition(t,SchedulerEvent.CAPTURE_SUCCESS)
    assert t.state==APState.VERIFYING
    sch.transition(t,SchedulerEvent.VERIFY_SUCCESS)
    assert t.state==APState.READY_TO_CRACK
    future=now+timedelta(seconds=11)
    assert len(sch.due_targets(future))>=1
