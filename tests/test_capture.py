from audit.capture.monitor import MonitorManager
from audit.capture.hcxdump import CaptureSession
from audit.capture.verifier import verify_capture

def test_imports():
    m=MonitorManager("wlan1")
    c=CaptureSession("aa:bb",1)
    assert m.interface=="wlan1"
    assert c.channel==1
    assert verify_capture("dummy")==False
