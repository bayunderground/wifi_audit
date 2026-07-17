from __future__ import annotations
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

from main import run_test_crack_mode, _extract_essid_from_hash, _save_cracked_results


class TestExtractEssid:
    def test_extract_essid_from_valid_hash(self, tmp_path):
        hash_file = tmp_path / "test.22000"
        # ESSID "12345678+" = hex 31323334353637382b
        hash_file.write_text("WPA*02*aa*bb*cc*31323334353637382b*dd*ee*ff*01\n")
        assert _extract_essid_from_hash(hash_file) == "12345678+"

    def test_extract_essid_empty_file(self, tmp_path):
        hash_file = tmp_path / "empty.22000"
        hash_file.write_text("")
        assert _extract_essid_from_hash(hash_file) == "unknown"

    def test_extract_essid_malformed(self, tmp_path):
        hash_file = tmp_path / "bad.22000"
        hash_file.write_text("not a hash file")
        assert _extract_essid_from_hash(hash_file) == "unknown"


class TestSaveCrackedResults:
    def test_saves_results(self, tmp_path):
        output = tmp_path / "cracked.txt"
        _save_cracked_results([
            ("TestNet", "aa:bb:cc:dd:ee:ff", "pass123"),
            ("OtherNet", "11:22:33:44:55:55", "secret"),
        ], output)
        content = output.read_text()
        assert "TestNet | aa:bb:cc:dd:ee:ff | pass123" in content
        assert "OtherNet | 11:22:33:44:55:55 | secret" in content

    def test_empty_results(self, tmp_path):
        output = tmp_path / "cracked.txt"
        _save_cracked_results([], output)
        assert output.read_text() == ""


class TestTestCrackMode:
    @patch("main.crack", return_value="12345678+")
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=True)
    def test_full_pipeline(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.22000").write_text(
                "WPA*02*aa*bb*cc*31323334353637382b*dd*ee*ff*01\n"
            )

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            mock_verify.assert_called_once()
            mock_convert.assert_called_once()
            mock_crack.assert_called_once()
            assert mock_crack.call_args[1]["custom_charsets"] == {1: "+"}
            assert mock_crack.call_args[1]["potfile"] == "/dev/null"

            cracked_file = fixtures_dir / "cracked.txt"
            assert cracked_file.exists()
            content = cracked_file.read_text()
            assert "12345678+" in content
            assert "AA_BB_CC_DD_EE_FF" in content

    @patch("main.crack", return_value=None)
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=True)
    def test_crack_failure_no_cracked_file(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            mock_convert.assert_called_once()
            assert not (fixtures_dir / "cracked.txt").exists()

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
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.22000").write_text(
                "WPA*02*aa*bb*cc*31323334353637382b*dd*ee*ff*01\n"
            )

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

    @patch("main.crack", return_value="pass1")
    @patch("main.convert_to_22000")
    @patch("main.verify_capture", return_value=True)
    def test_multiple_fixtures(self, mock_verify, mock_convert, mock_crack):
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()
            (fixtures_dir / "AA_BB_CC_DD_EE_FF.22000").write_text(
                "WPA*02*aa*bb*cc*4e657431*dd*ee*ff*01\n"
            )
            (fixtures_dir / "11_22_33_44_55_66.pcapng").touch()
            (fixtures_dir / "11_22_33_44_55_66.22000").write_text(
                "WPA*02*aa*bb*cc*4e657432*dd*ee*ff*01\n"
            )

            cfg = Mock()
            log = Mock()
            args = Mock()
            args.mask = None

            run_test_crack_mode(cfg, log, args, fixtures_dir=fixtures_dir)

            assert mock_crack.call_count == 2
            cracked_file = fixtures_dir / "cracked.txt"
            assert cracked_file.exists()
            lines = cracked_file.read_text().strip().split("\n")
            assert len(lines) == 2
