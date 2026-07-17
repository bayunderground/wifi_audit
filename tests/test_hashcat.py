import pytest
from unittest.mock import patch
from audit.crack.hashcat import crack, HashcatError
from audit.util.subprocess import CommandError

HASHCAT_OUTPUT_CRACKED = """\
hashcat (v6.2.6) starting...

aa:bb:cc:dd:ee:ff:12345678
"""

HASHCAT_OUTPUT_NOT_CRACKED = """\
hashcat (v6.2.6) starting...

Session..........: hashcat
Status........: Exhausted
"""

@patch("audit.crack.hashcat.run", return_value=HASHCAT_OUTPUT_CRACKED)
def test_crack_success(mock_run):
    result = crack("test.22000", "?d?d?d?d?d?d?d?d")
    assert result == "12345678"
    mock_run.assert_called_once_with(["hashcat", "-m", "22000", "test.22000", "?d?d?d?d?d?d?d?d"])

@patch("audit.crack.hashcat.run", return_value=HASHCAT_OUTPUT_NOT_CRACKED)
def test_crack_not_found(mock_run):
    result = crack("test.22000", "?d?d?d?d?d?d?d?d")
    assert result is None

@patch("audit.crack.hashcat.run", side_effect=CommandError(["hashcat"], 1, "no gpu"))
def test_crack_error(mock_run):
    with pytest.raises(HashcatError):
        crack("test.22000", "?d?d?d?d?d?d?d?d")

@patch("audit.crack.hashcat.run", return_value=HASHCAT_OUTPUT_CRACKED)
def test_crack_with_custom_charsets(mock_run):
    result = crack("test.22000", "12345678?1", custom_charsets={1: "+"})
    assert result == "12345678"
    mock_run.assert_called_once_with(["hashcat", "-m", "22000", "test.22000", "-a", "3", "-1", "+", "12345678?1"])
