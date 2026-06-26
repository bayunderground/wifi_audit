from pathlib import Path
from unittest.mock import patch, MagicMock
from audit.capture.hcxdump import CaptureSession

@patch("audit.capture.hcxdump.Popen")
def test_start(mock_popen_cls):
    mock_popen = MagicMock()
    mock_popen_cls.return_value = mock_popen
    cap = CaptureSession("wlan1mon", "aa:bb:cc:dd:ee:ff", 6, Path("captures/test.pcapng"))
    cap.start()
    mock_popen_cls.assert_called_once_with([
        "hcxdumptool", "-i", "wlan1mon",
        "--bssid", "aa:bb:cc:dd:ee:ff",
        "--channel", "6",
        "-w", "captures/test.pcapng",
    ])
    mock_popen.start.assert_called_once()

@patch("audit.capture.hcxdump.Popen")
def test_stop(mock_popen_cls):
    mock_popen = MagicMock()
    mock_popen_cls.return_value = mock_popen
    cap = CaptureSession("wlan1mon", "aa:bb", 6, Path("out.pcapng"))
    cap.start()
    cap.stop()
    mock_popen.stop.assert_called_once()
    assert cap._backend is None

def test_stop_without_start():
    cap = CaptureSession("wlan1mon", "aa:bb", 6, Path("out.pcapng"))
    cap.stop()

@patch("audit.capture.hcxdump.run", return_value="PMKID:1 EAPOL:0\n")
@patch("builtins.open", MagicMock())
def test_handshake_detected_pmkid(mock_run):
    cap = CaptureSession("wlan1mon", "aa:bb", 6, Path("out.pcapng"))
    with patch.object(Path, "exists", return_value=True):
        assert cap.handshake_detected() is True

@patch("audit.capture.hcxdump.run", return_value="PMKID:0 EAPOL:4\n")
@patch("builtins.open", MagicMock())
def test_handshake_detected_eapol(mock_run):
    cap = CaptureSession("wlan1mon", "aa:bb", 6, Path("out.pcapng"))
    with patch.object(Path, "exists", return_value=True):
        assert cap.handshake_detected() is True

@patch("audit.capture.hcxdump.run", return_value="PMKID:0 EAPOL:0\n")
@patch("builtins.open", MagicMock())
def test_handshake_not_detected(mock_run):
    cap = CaptureSession("wlan1mon", "aa:bb", 6, Path("out.pcapng"))
    with patch.object(Path, "exists", return_value=True):
        assert cap.handshake_detected() is False

def test_handshake_no_file():
    cap = CaptureSession("wlan1mon", "aa:bb", 6, Path("nonexistent.pcapng"))
    assert cap.handshake_detected() is False
