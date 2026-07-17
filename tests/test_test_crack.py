from __future__ import annotations
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

from main import run_test_crack_mode


class TestTestCrackMode:
    @patch("main.crack", return_value="12345678+")
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=True)
    def test_full_pipeline(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            mock_verify.assert_called_once()
            mock_convert.assert_called_once()
            mock_crack.assert_called_once()
            assert mock_crack.call_args[1]["custom_charsets"] == {1: "+"}

    @patch("main.crack", return_value=None)
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=True)
    def test_crack_failure(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            mock_convert.assert_called_once()
            log.info.assert_any_call("Password not found: %s", "AA_BB_CC_DD_EE_FF.pcapng")

    @patch("main.crack")
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=False)
    def test_verify_failure_skips_conversion(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            mock_convert.assert_not_called()
            mock_crack.assert_not_called()

    @patch("main.verify_capture")
    def test_no_fixtures(self, mock_verify):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            mock_verify.assert_not_called()
            log.info.assert_called_with("No fixture capture files found in %s", fixtures_dir)

    @patch("main.crack", return_value="12345678+")
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=True)
    def test_custom_mask_passthrough(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = "?d?d?d?d?d?d?d?d"

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            mock_crack.assert_called_once()
            assert mock_crack.call_args[0][1] == "?d?d?d?d?d?d?d?d"
            assert mock_crack.call_args[1]["custom_charsets"] is None

    @patch("main.crack", side_effect=Exception("hashcat error"))
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=True)
    def test_exception_handling(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            log.error.assert_called()
