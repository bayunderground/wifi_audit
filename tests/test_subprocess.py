from unittest.mock import patch, MagicMock
from audit.util.subprocess import run, CommandError

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
    try:
        run(["bad", "cmd"])
        assert False, "Should have raised"
    except CommandError as e:
        assert e.cmd == ["bad", "cmd"]
        assert e.returncode == 1
        assert e.stderr == "not found"

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
