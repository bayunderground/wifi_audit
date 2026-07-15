from __future__ import annotations
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, call
import pytest

from main import run_verify_mode


class TestVerifyMode:
    @patch("main.convert_to_22000")
    @patch("main.verify_capture")
    def test_verify_mode_processes_all_captures(self, mock_verify, mock_convert):
        mock_verify.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            captures_dir = Path(tmpdir) / "captures"
            hashes_dir = Path(tmpdir) / "hashes"
            captures_dir.mkdir()

            (captures_dir / "AA_BB_CC_DD_EE_FF.pcapng").touch()
            (captures_dir / "11_22_33_44_55_66.pcapng").touch()

            cfg = Mock()
            cfg.paths.captures = str(captures_dir)
            cfg.paths.hashes = str(hashes_dir)

            log = Mock()

            run_verify_mode(cfg, log)

            assert mock_verify.call_count == 2
            assert mock_convert.call_count == 2
            assert hashes_dir.exists()

    @patch("main.convert_to_22000")
    @patch("main.verify_capture")
    def test_verify_mode_skips_invalid_captures(self, mock_verify, mock_convert):
        mock_verify.side_effect = [True, False, True]

        with tempfile.TemporaryDirectory() as tmpdir:
            captures_dir = Path(tmpdir) / "captures"
            hashes_dir = Path(tmpdir) / "hashes"
            captures_dir.mkdir()

            (captures_dir / "valid1.pcapng").touch()
            (captures_dir / "invalid.pcapng").touch()
            (captures_dir / "valid2.pcapng").touch()

            cfg = Mock()
            cfg.paths.captures = str(captures_dir)
            cfg.paths.hashes = str(hashes_dir)

            log = Mock()

            run_verify_mode(cfg, log)

            assert mock_verify.call_count == 3
            assert mock_convert.call_count == 2

    @patch("main.convert_to_22000")
    @patch("main.verify_capture")
    def test_verify_mode_handles_conversion_errors(self, mock_verify, mock_convert):
        mock_verify.return_value = True
        mock_convert.side_effect = Exception("Conversion failed")

        with tempfile.TemporaryDirectory() as tmpdir:
            captures_dir = Path(tmpdir) / "captures"
            hashes_dir = Path(tmpdir) / "hashes"
            captures_dir.mkdir()

            (captures_dir / "test.pcapng").touch()

            cfg = Mock()
            cfg.paths.captures = str(captures_dir)
            cfg.paths.hashes = str(hashes_dir)

            log = Mock()

            run_verify_mode(cfg, log)

            assert mock_verify.call_count == 1
            assert mock_convert.call_count == 1
            log.error.assert_called()

    @patch("main.verify_capture")
    def test_verify_mode_no_captures_found(self, mock_verify):
        with tempfile.TemporaryDirectory() as tmpdir:
            captures_dir = Path(tmpdir) / "captures"
            hashes_dir = Path(tmpdir) / "hashes"
            captures_dir.mkdir()

            cfg = Mock()
            cfg.paths.captures = str(captures_dir)
            cfg.paths.hashes = str(hashes_dir)

            log = Mock()

            run_verify_mode(cfg, log)

            mock_verify.assert_not_called()
            log.info.assert_called_with("No capture files found in %s", captures_dir)

    @patch("main.convert_to_22000")
    @patch("main.verify_capture")
    def test_verify_mode_creates_hash_directory(self, mock_verify, mock_convert):
        mock_verify.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            captures_dir = Path(tmpdir) / "captures"
            hashes_dir = Path(tmpdir) / "hashes"
            captures_dir.mkdir()

            (captures_dir / "test.pcapng").touch()

            cfg = Mock()
            cfg.paths.captures = str(captures_dir)
            cfg.paths.hashes = str(hashes_dir)

            log = Mock()

            run_verify_mode(cfg, log)

            assert hashes_dir.exists()
            assert hashes_dir.is_dir()
