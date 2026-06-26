from pathlib import Path
from unittest.mock import patch
from audit.capture.monitor import MonitorManager
from audit.capture.hcxdump import CaptureSession
from audit.capture.verifier import verify_capture

def test_imports():
    m = MonitorManager("wlan1")
    c = CaptureSession("wlan1mon", "aa:bb", 1, Path("out.pcapng"))
    assert m.interface == "wlan1"
    assert c.channel == 1
    assert c.bssid == "aa:bb"

@patch("audit.capture.verifier.run", return_value="PMKID:0 EAPOL:0\n")
def test_verify_capture_mocked(mock_run):
    assert verify_capture("dummy") is False
