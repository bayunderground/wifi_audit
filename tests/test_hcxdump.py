from pathlib import Path
from unittest.mock import patch, MagicMock, call
from audit.capture.hcxdump import CaptureSession, _channel_arg, _compile_bpf

def test_channel_arg_2ghz():
    assert _channel_arg(1) == "1"
    assert _channel_arg(6) == "6"
    assert _channel_arg(14) == "14"

def test_channel_arg_5ghz():
    assert _channel_arg(36) == "36"
    assert _channel_arg(44) == "44"
    assert _channel_arg(149) == "149"

@patch("audit.capture.hcxdump.run", return_value="48 0 0 3\n100 0 0 8\n")
def test_compile_bpf(mock_run):
    result = _compile_bpf("aa:bb:cc:dd:ee:ff")
    mock_run.assert_called_once_with(["hcxdumptool", "--bpfc=wlan addr3 aabbccddeeff"])
    assert "48 0 0 3" in result

@patch("audit.capture.hcxdump._compile_bpf", return_value="48 0 0 3\n")
@patch("audit.capture.hcxdump.Popen")
def test_start(mock_popen_cls, mock_bpf):
    mock_popen = MagicMock()
    mock_popen_cls.return_value = mock_popen
    cap = CaptureSession("wlan1", "aa:bb:cc:dd:ee:ff", 6, Path("captures/test.pcapng"))
    with patch("audit.capture.hcxdump.tempfile.NamedTemporaryFile") as mock_tmp:
        mock_file = MagicMock()
        mock_file.name = "/tmp/test.bpf"
        mock_tmp.return_value = mock_file
        cap.start()
    mock_bpf.assert_called_once_with("aa:bb:cc:dd:ee:ff")
    mock_popen_cls.assert_called_once_with([
        "hcxdumptool", "-i", "wlan1",
        "-c", "6",
        "--bpf", "/tmp/test.bpf",
        "-w", "captures/test.pcapng",
    ])
    mock_popen.start.assert_called_once()

@patch("audit.capture.hcxdump._compile_bpf", return_value="48 0 0 3\n")
@patch("audit.capture.hcxdump.Popen")
def test_stop(mock_popen_cls, mock_bpf):
    mock_popen = MagicMock()
    mock_popen_cls.return_value = mock_popen
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    with patch("audit.capture.hcxdump.tempfile.NamedTemporaryFile") as mock_tmp:
        mock_file = MagicMock()
        mock_file.name = "/tmp/test.bpf"
        mock_tmp.return_value = mock_file
        cap.start()
    cap.stop()
    mock_popen.stop.assert_called_once()
    assert cap._backend is None
    assert cap._bpf_path is None

def test_stop_without_start():
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    cap.stop()

@patch("audit.capture.hcxdump.run", return_value="PMKID total.....................: 1\nEAPOL pairs (useful).....................: 0\n")
def test_handshake_detected_pmkid(mock_run):
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "stat") as mock_stat:
        mock_stat.return_value.st_size = 100
        assert cap.handshake_detected() is True

@patch("audit.capture.hcxdump.run", return_value="PMKID total.....................: 0\nEAPOL pairs (useful).....................: 4\n")
def test_handshake_detected_eapol(mock_run):
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "stat") as mock_stat:
        mock_stat.return_value.st_size = 100
        assert cap.handshake_detected() is True

@patch("audit.capture.hcxdump.run", return_value="PMKID total.....................: 0\nEAPOL pairs (useful).....................: 0\n")
def test_handshake_not_detected(mock_run):
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "stat") as mock_stat:
        mock_stat.return_value.st_size = 100
        assert cap.handshake_detected() is False

def test_handshake_no_file():
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("nonexistent.pcapng"))
    assert cap.handshake_detected() is False

def test_handshake_empty_file():
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "stat") as mock_stat:
        mock_stat.return_value.st_size = 0
        assert cap.handshake_detected() is False

def test_timed_out_before_start():
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    assert cap.timed_out(90) is False

@patch("audit.capture.hcxdump._compile_bpf", return_value="48 0 0 3\n")
@patch("audit.capture.hcxdump.Popen")
def test_timed_out_not_yet(mock_popen_cls, mock_bpf):
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    with patch("audit.capture.hcxdump.tempfile.NamedTemporaryFile") as mock_tmp:
        mock_file = MagicMock()
        mock_file.name = "/tmp/test.bpf"
        mock_tmp.return_value = mock_file
        cap.start()
    assert cap.timed_out(9999) is False

@patch("audit.capture.hcxdump._compile_bpf", return_value="48 0 0 3\n")
@patch("audit.capture.hcxdump.Popen")
@patch("audit.capture.hcxdump.time")
def test_timed_out_expired(mock_time, mock_popen_cls, mock_bpf):
    mock_time.monotonic.side_effect = [100.0, 200.0]
    cap = CaptureSession("wlan1", "aa:bb", 6, Path("out.pcapng"))
    with patch("audit.capture.hcxdump.tempfile.NamedTemporaryFile") as mock_tmp:
        mock_file = MagicMock()
        mock_file.name = "/tmp/test.bpf"
        mock_tmp.return_value = mock_file
        cap.start()
    assert cap.timed_out(90) is True
