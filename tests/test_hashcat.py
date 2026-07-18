import pytest
from unittest.mock import patch, MagicMock
from audit.crack.hashcat import crack, HashcatError


HASHCAT_OUTPUT_CRACKED = """\
hashcat (v6.2.6) starting...

aa:bb:cc:dd:ee:ff:12345678
"""

HASHCAT_OUTPUT_NOT_CRACKED = """\
hashcat (v6.2.6) starting...

Session..........: hashcat
Status........: Exhausted
"""

def _make_result(stdout="", stderr="", returncode=0):
    r = MagicMock()
    r.stdout = stdout
    r.stderr = stderr
    r.returncode = returncode
    return r


@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(HASHCAT_OUTPUT_CRACKED))
def test_crack_success(mock_run):
    result = crack("test.22000", "?d?d?d?d?d?d?d?d")
    assert result == "12345678"
    cmd = mock_run.call_args[0][0]
    assert cmd == ["hashcat", "-m", "22000", "test.22000", "?d?d?d?d?d?d?d?d"]

@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(HASHCAT_OUTPUT_NOT_CRACKED))
def test_crack_not_found(mock_run):
    result = crack("test.22000", "?d?d?d?d?d?d?d?d")
    assert result is None

@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(stderr="no gpu", returncode=255))
def test_crack_error(mock_run):
    with pytest.raises(HashcatError):
        crack("test.22000", "?d?d?d?d?d?d?d?d")

@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(HASHCAT_OUTPUT_CRACKED))
def test_crack_with_custom_charsets(mock_run):
    result = crack("test.22000", "12345678?1", custom_charsets={1: "+"})
    assert result == "12345678"
    cmd = mock_run.call_args[0][0]
    assert cmd == ["hashcat", "-m", "22000", "-a", "3", "-1", "+", "test.22000", "12345678?1"]

@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(HASHCAT_OUTPUT_CRACKED))
def test_crack_with_potfile(mock_run):
    result = crack("test.22000", "?d?d?d?d?d?d?d?d", potfile="/dev/null")
    assert result == "12345678"
    cmd = mock_run.call_args[0][0]
    assert cmd == ["hashcat", "-m", "22000", "--potfile-path", "/dev/null", "test.22000", "?d?d?d?d?d?d?d?d"]

HASHCAT_OUTPUT_WITH_URL = """\
hashcat (v6.2.6) starting...

OpenCL API (OpenCL 3.0 ...
* Device #1: Tesla V100-SXM2-16GB, 14751/16160 MB, 80MCU

aa:bb:cc:dd:ee:ff:12345678

Session..........: hashcat
Status...........: Cracked
"""

@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(HASHCAT_OUTPUT_WITH_URL))
def test_crack_ignores_urls_in_output(mock_run):
    result = crack("test.22000", "?d?d?d?d?d?d?d?d")
    assert result == "12345678"

HASHCAT_OUTPUT_URL_ONLY = """\
hashcat (v6.2.6) starting...

STATUS: PASS //hashcat.net/faq/morework

Session..........: hashcat
Status...........: Exhausted
"""

@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(HASHCAT_OUTPUT_URL_ONLY))
def test_crack_does_not_match_urls(mock_run):
    result = crack("test.22000", "?d?d?d?d?d?d?d?d")
    assert result is None

HASHCAT_OUTPUT_WPA = """\
hashcat (v6.2.6) starting...

WPA*02*43e1f4029b39cdd48bd8169920e9d2d6*9c9d7ecfdc80*222351001162*31323334353637382b*edcb4ef03ef9f854f6a218e104d06236c6b2ca5a7b7a84d40790bccac8d4b57a*0103007502010a0000000000000000*10:12345678+
"""

@patch("audit.crack.hashcat._subprocess.run", return_value=_make_result(HASHCAT_OUTPUT_WPA))
def test_crack_wpa_hash_format(mock_run):
    result = crack("test.22000", "12345678?1", custom_charsets={1: "+"})
    assert result == "12345678+"
