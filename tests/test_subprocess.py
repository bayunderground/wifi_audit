import pytest
from unittest.mock import patch, MagicMock, ANY
from audit.util.subprocess import run, CommandError, Popen

@patch("audit.util.subprocess._subprocess.run")
def test_run_success(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="output\n", stderr="")
    result = run(["echo", "hello"])
    assert result == "output\n"
    mock_run.assert_called_once_with(
        ["echo", "hello"],
        text=True,
        capture_output=True,
        timeout=None,
    )

@patch("audit.util.subprocess._subprocess.run")
def test_run_failure(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
    with pytest.raises(CommandError) as exc_info:
        run(["bad", "cmd"])
    assert exc_info.value.cmd == ["bad", "cmd"]
    assert exc_info.value.returncode == 1
    assert exc_info.value.stderr == "not found"

@patch("audit.util.subprocess._subprocess.run")
def test_run_timeout(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
    run(["cmd"], timeout=30)
    mock_run.assert_called_once_with(
        ["cmd"],
        text=True,
        capture_output=True,
        timeout=30,
    )

@patch("audit.util.subprocess._subprocess.Popen")
def test_popen_start(mock_popen_cls):
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_popen_cls.return_value = mock_proc
    p = Popen(["cmd", "arg"])
    p.start()
    mock_popen_cls.assert_called_once_with(
        ["cmd", "arg"],
        text=True,
        stdout=ANY,
        stderr=ANY,
    )
    assert p.running is True

@patch("audit.util.subprocess._subprocess.Popen")
def test_popen_stop(mock_popen_cls):
    mock_proc = MagicMock()
    mock_popen_cls.return_value = mock_proc
    p = Popen(["cmd"])
    p.start()
    p.stop()
    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_called_once_with(timeout=10)
    assert p.running is False

def test_popen_stop_without_start():
    p = Popen(["cmd"])
    p.stop()

@patch("audit.util.subprocess._subprocess.Popen")
def test_popen_running(mock_popen_cls):
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_popen_cls.return_value = mock_proc
    p = Popen(["cmd"])
    p.start()
    assert p.running is True
    mock_proc.poll.return_value = 0
    assert p.running is False
