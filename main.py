from __future__ import annotations
import argparse
import signal
import sys
import time
from pathlib import Path

from audit.config import load_config
from audit.logging import setup_logging, get_logger
from audit.persistence import load_raw, save_raw
from audit.models import AuditState, AuditTarget, APState
from audit.scheduler import Scheduler, SchedulerEvent
from audit.scanner import scan
from audit.capture.monitor import MonitorManager
from audit.capture.hcxdump import CaptureSession
from audit.capture.verifier import verify_capture
from audit.capture.converter import convert_to_22000
from audit.crack.hashcat import crack
from audit.report.report import generate_report

log = get_logger(__name__)

def _extract_essid_from_hash(hash_file: Path) -> str:
    """Extract ESSID from a .22000 hash file (hex-encoded field 6)."""
    try:
        line = hash_file.read_text().strip().split("\n")[0]
        parts = line.split("*")
        if len(parts) >= 6:
            return bytes.fromhex(parts[5]).decode(errors="replace")
    except Exception:
        pass
    return "unknown"

def _save_cracked_results(results: list[tuple[str, str, str]], output_path: Path) -> None:
    """Save cracked results to a file. Each entry: (essid, bssid, password)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{essid} | {bssid} | {password}" for essid, bssid, password in results]
    output_path.write_text("\n".join(lines) + "\n" if lines else "")
    log.info("Cracked results saved to %s", output_path)

def run_verify_mode(cfg, log) -> None:
    """Verify and convert all available captures to .22000 format."""
    captures_dir = Path(cfg.paths.captures)
    hashes_dir = Path(cfg.paths.hashes)
    hashes_dir.mkdir(parents=True, exist_ok=True)

    capture_files = list(captures_dir.glob("*.pcapng"))
    if not capture_files:
        log.info("No capture files found in %s", captures_dir)
        return

    log.info("Found %d capture files to verify", len(capture_files))

    verified_count = 0
    converted_count = 0
    failed_count = 0

    for capture_file in capture_files:
        bssid = capture_file.stem.replace('_', ':')
        log.info("Processing: %s (%s)", capture_file.name, bssid)

        try:
            if verify_capture(str(capture_file)):
                verified_count += 1
                hash_file = hashes_dir / f"{capture_file.stem}.22000"

                try:
                    convert_to_22000(str(capture_file), str(hash_file))
                    converted_count += 1
                    log.info("Converted: %s -> %s", capture_file.name, hash_file.name)
                except Exception as e:
                    log.error("Conversion failed for %s: %s", capture_file.name, e)
                    failed_count += 1
            else:
                log.info("No valid handshake/PMKID in %s", capture_file.name)
                failed_count += 1
        except Exception as e:
            log.error("Verification failed for %s: %s", capture_file.name, e)
            failed_count += 1

    log.info("Verification complete: %d verified, %d converted, %d failed",
             verified_count, converted_count, failed_count)

def run_crack_mode(cfg, log) -> None:
    """Crack all READY_TO_CRACK targets from existing .22000 hash files."""
    raw = load_raw(cfg.paths.state)
    state = AuditState()
    state.targets = raw
    log.info("Loaded %d targets", len(state.targets))

    candidates = {
        bssid: t for bssid, t in state.targets.items()
        if t.state == APState.READY_TO_CRACK and t.hash_path
    }

    if not candidates:
        log.info("No targets ready to crack")
        return

    log.info("Found %d targets ready to crack", len(candidates))

    cracked_count = 0
    cracked_results: list[tuple[str, str, str]] = []
    for bssid, target in candidates.items():
        log.info("Cracking %s (%s)", target.ap.essid, bssid)
        try:
            password = crack(str(target.hash_path), cfg.cracking.mask)
            if password:
                target.password = password
                target.state = APState.CRACKED
                cracked_count += 1
                cracked_results.append((target.ap.essid, bssid, password))
                log.info("Cracked: %s -> %s", bssid, password)
            else:
                log.info("Password not found: %s", bssid)
        except Exception as e:
            log.error("Cracking failed for %s: %s", bssid, e)

    generate_report(state, Path(cfg.paths.reports))
    if cracked_results:
        _save_cracked_results(cracked_results, Path(cfg.paths.reports) / "cracked.txt")
    save_raw(cfg.paths.state, state.targets)
    log.info("Crack complete: %d/%d cracked", cracked_count, len(candidates))

def run_test_crack_mode(cfg, log, args, fixtures_dir: str | Path = "fixtures") -> None:
    """Test crack using pre-saved fixture files. Bypasses all filters."""
    fixtures_dir = Path(fixtures_dir)

    capture_files = list(fixtures_dir.glob("*.pcapng"))
    if not capture_files:
        log.info("No fixture capture files found in %s", fixtures_dir)
        return

    log.info("Found %d fixture capture files", len(capture_files))

    cracked_count = 0
    cracked_results: list[tuple[str, str, str]] = []
    for capture_file in capture_files:
        log.info("Processing fixture: %s", capture_file.name)

        try:
            if not verify_capture(str(capture_file)):
                log.info("No valid handshake in %s", capture_file.name)
                continue

            hash_file = fixtures_dir / f"{capture_file.stem}.22000"
            convert_to_22000(str(capture_file), str(hash_file))
            log.info("Converted: %s -> %s", capture_file.name, hash_file.name)

            mask = args.mask or "12345678?1"
            custom_charsets = {1: "+"} if not args.mask else None
            password = crack(str(hash_file), mask, custom_charsets=custom_charsets, potfile="/dev/null")
            if password:
                cracked_count += 1
                essid = _extract_essid_from_hash(hash_file)
                cracked_results.append((essid, capture_file.stem, password))
                log.info("Cracked: %s -> %s", capture_file.name, password)
            else:
                log.info("Password not found: %s", capture_file.name)
        except Exception as e:
            log.error("Failed for %s: %s", capture_file.name, e)

    if cracked_results:
        _save_cracked_results(cracked_results, fixtures_dir / "cracked.txt")
    log.info("Test crack complete: %d/%d cracked", cracked_count, len(capture_files))

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Wi-Fi audit framework")
    p.add_argument("mode", choices=["capture", "crack", "verify", "test-crack"], help="Operating mode")
    p.add_argument("-c", "--config", default="config/config.yaml", help="Config file path")
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Override log level from config")
    p.add_argument("--mask", default=None, help="Override cracking mask (test-crack only)")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    if args.log_level:
        cfg.logging.level = args.log_level
    setup_logging(cfg.logging, cfg.paths.logs)
    log = get_logger(__name__)

    if args.mode == "verify":
        run_verify_mode(cfg, log)
        return

    if args.mode == "crack":
        run_crack_mode(cfg, log)
        return

    if args.mode == "test-crack":
        run_test_crack_mode(cfg, log, args)
        return

    raw = load_raw(cfg.paths.state)
    state = AuditState()
    log.info("Loaded %d targets", len(state.targets))

    monitor = MonitorManager(cfg.interfaces.monitor)
    scheduler = Scheduler(state, cfg.capture.revisit_interval)

    active_captures: dict[str, CaptureSession] = {}
    running = True

    def handle_sigint(sig: int, frame: object) -> None:
        nonlocal running
        log.info("Shutting down...")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    # Scan while interface is still in managed mode
    try:
        raw_scan = scan(cfg.interfaces.monitor, cfg.filters.whitelist, cfg.filters.blacklist)
        for ap in raw_scan.access_points:
            if ap.bssid not in state.targets:
                log.info("New AP: %s (%s)", ap.essid, ap.bssid)
                state.targets[ap.bssid] = AuditTarget(ap=ap, state=APState.DISCOVERED)
                scheduler.rebuild()
    except Exception as e:
        log.error("Initial scan failed: %s", e)
        sys.exit(1)

    if not state.targets:
        log.error("No targets found. Check filters or bring APs in range.")
        sys.exit(1)

    log.info("Discovered %d targets, enabling monitor mode", len(state.targets))

    try:
        monitor.enable()
    except Exception as e:
        log.error("Failed to enable monitor mode: %s", e)
        sys.exit(1)

    try:
        while running:
            for target in scheduler.due_targets():
                if not running:
                    break

                if target.state in (APState.DISCOVERED, APState.WAITING_FOR_CLIENT):
                    # Single radio: stop any existing capture before switching
                    for bssid, existing_cap in list(active_captures.items()):
                        if bssid != target.ap.bssid:
                            log.info("Stopping capture for %s to switch to %s",
                                     bssid, target.ap.bssid)
                            existing_cap.stop()
                            interrupted = state.targets.get(bssid)
                            if interrupted and interrupted.state == APState.CAPTURING:
                                scheduler.transition(interrupted, SchedulerEvent.CAPTURE_TIMEOUT)
                            del active_captures[bssid]

                    if target.ap.bssid not in active_captures:
                        log.info("Starting capture: %s", target.ap.bssid)
                        cap_path = Path(cfg.paths.captures) / f"{target.ap.bssid.replace(':', '_')}.pcapng"
                        cap = CaptureSession(
                            monitor.monitor_iface, target.ap.bssid, target.ap.channel, cap_path
                        )
                        cap.start()
                        active_captures[target.ap.bssid] = cap
                        target.handshake_path = cap_path
                        scheduler.transition(target, SchedulerEvent.CLIENTS_PRESENT)
                    break  # one capture at a time; let it run before checking others

                elif target.state == APState.CAPTURING:
                    cap = active_captures.get(target.ap.bssid)
                    if cap is None:
                        scheduler.transition(target, SchedulerEvent.CAPTURE_TIMEOUT)
                    elif cap.handshake_detected():
                        log.info("Handshake found: %s", target.ap.bssid)
                        cap.stop()
                        del active_captures[target.ap.bssid]
                        scheduler.transition(target, SchedulerEvent.CAPTURE_SUCCESS)
                    elif cap.timed_out(cfg.capture.handshake_timeout):
                        log.info("Capture timed out after %ds: %s",
                                 cfg.capture.handshake_timeout, target.ap.bssid)
                        cap.stop()
                        del active_captures[target.ap.bssid]
                        scheduler.transition(target, SchedulerEvent.CAPTURE_TIMEOUT)
                    else:
                        log.debug("No handshake yet: %s", target.ap.bssid)
                    break  # one capture at a time

                elif target.state == APState.VERIFYING:
                    if target.handshake_path and verify_capture(str(target.handshake_path)):
                        log.info("Capture verified: %s", target.ap.bssid)
                        hash_path = Path(cfg.paths.hashes) / f"{target.ap.bssid.replace(':', '_')}.22000"
                        convert_to_22000(str(target.handshake_path), str(hash_path))
                        target.hash_path = hash_path
                        scheduler.transition(target, SchedulerEvent.VERIFY_SUCCESS)
                    else:
                        log.info("Verification failed: %s", target.ap.bssid)
                        scheduler.transition(target, SchedulerEvent.VERIFY_FAILED)

                elif target.state == APState.READY_TO_CRACK:
                    if args.mode == "crack" and target.hash_path:
                        log.info("Cracking: %s", target.ap.bssid)
                        password = crack(str(target.hash_path), cfg.cracking.mask)
                        if password:
                            target.password = password
                            target.state = APState.CRACKED
                            log.info("Cracked: %s -> %s", target.ap.bssid, password)

            generate_report(state, Path(cfg.paths.reports))
            save_raw(cfg.paths.state, state.targets)
            time.sleep(5)

    finally:
        for cap in active_captures.values():
            cap.stop()
        active_captures.clear()
        monitor.disable()
        save_raw(cfg.paths.state, state.targets)
        log.info("State saved. Exiting.")

if __name__ == "__main__":
    main()
