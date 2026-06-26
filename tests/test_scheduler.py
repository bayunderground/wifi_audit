
from datetime import datetime,timedelta
from audit.scheduler import Scheduler,SchedulerEvent
from audit.models import AccessPoint,AuditTarget,AuditState,APState

ap=AccessPoint("TP-Link_Test","aa",1,-40,"WPA2")
t=AuditTarget(ap=ap,state=APState.DISCOVERED)
st=AuditState(targets={"aa":t})
sch=Scheduler(st,10)

assert len(sch.due_targets(datetime.utcnow()))==1
sch.transition(t,SchedulerEvent.CLIENTS_PRESENT)
assert t.state==APState.CAPTURING
sch.transition(t,SchedulerEvent.CAPTURE_SUCCESS)
assert t.state==APState.VERIFYING
sch.transition(t,SchedulerEvent.VERIFY_SUCCESS)
assert t.state==APState.READY_TO_CRACK
future=datetime.utcnow()+timedelta(seconds=11)
assert len(sch.due_targets(future))>=1
