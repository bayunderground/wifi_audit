from pathlib import Path
from audit.capture.monitor import MonitorManager
from audit.capture.hcxdump import CaptureSession
from audit.capture.verifier import verify_capture

def test_imports():
    m = MonitorManager("wlan1")
    c = CaptureSession("wlan1mon", "aa:bb", 1, Path("out.pcapng"))
    assert m.interface == "wlan1"
    assert c.channel == 1
    assert c.bssid == "aa:bb"
    assert verify_capture("dummy") == False
