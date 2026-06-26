import pytest
from unittest.mock import patch
from audit.capture.verifier import verify_capture, VerificationError
from audit.util.subprocess import CommandError

@patch("audit.capture.verifier.run", return_value="PMKID:1 EAPOL:0\n")
def test_verify_pmkid(mock_run):
    assert verify_capture("test.pcapng") is True
    mock_run.assert_called_once_with(["hcxpcapngtool", "--all", "test.pcapng"])

@patch("audit.capture.verifier.run", return_value="PMKID:0 EAPOL:4\n")
def test_verify_eapol(mock_run):
    assert verify_capture("test.pcapng") is True

@patch("audit.capture.verifier.run", return_value="PMKID:0 EAPOL:0\n")
def test_verify_no_hash(mock_run):
    assert verify_capture("test.pcapng") is False

@patch("audit.capture.verifier.run", side_effect=CommandError(["hcxpcapngtool"], 1, "file not found"))
def test_verify_command_error(mock_run):
    with pytest.raises(VerificationError):
        verify_capture("bad.pcapng")
