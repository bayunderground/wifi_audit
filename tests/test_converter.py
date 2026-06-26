import pytest
from unittest.mock import patch
from audit.capture.converter import convert_to_22000, ConversionError
from audit.util.subprocess import CommandError

@patch("audit.capture.converter.run")
def test_convert_success(mock_run):
    convert_to_22000("input.pcapng", "output.22000")
    mock_run.assert_called_once_with(["hcxpcapngtool", "-o", "output.22000", "input.pcapng"])

@patch("audit.capture.converter.run", side_effect=CommandError(["hcxpcapngtool"], 1, "bad file"))
def test_convert_failure(mock_run):
    with pytest.raises(ConversionError):
        convert_to_22000("bad.pcapng", "out.22000")
