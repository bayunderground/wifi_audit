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

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Wi-Fi audit framework")
    p.add_argument("-c", "--config", default="config/config.yaml", help="Config file path")
    p.add_argument("--whitelist", nargs="+", help="Override whitelist regex list")
    p.add_argument("--blacklist", nargs="+", help="Override blacklist regex list")
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Override log level from config")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    if args.log_level:
        cfg.logging.level = args.log_level
    setup_logging(cfg.logging, cfg.paths.logs)
    log = get_logger(__name__)

    raw = load_raw(cfg.paths.state)
    state = AuditState()
    log.info("Loaded %d targets", len(state.targets))

    whitelist = args.whitelist if args.whitelist is not None else cfg.filters.whitelist
    blacklist = args.blacklist if args.blacklist is not None else cfg.filters.blacklist

    monitor = MonitorManager(cfg.interfaces.monitor)
    scheduler = Scheduler(state, cfg.capture.revisit_interval)

    active_capture: CaptureSession | None = None
    running = True

    def handle_sigint(sig: int, frame: object) -> None:
        nonlocal running
        log.info("Shutting down...")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    try:
        monitor.enable()
    except Exception as e:
        log.error("Failed to enable monitor mode: %s", e)
        sys.exit(1)

    try:
        while running:
            raw_scan = scan(cfg.interfaces.monitor, whitelist, blacklist)
            for ap in raw_scan.access_points:
                if ap.bssid not in state.targets:
                    log.info("New AP: %s (%s)", ap.essid, ap.bssid)
                    state.targets[ap.bssid] = AuditTarget(ap=ap, state=APState.DISCOVERED)
                    scheduler.rebuild()

            for target in scheduler.due_targets():
                if not running:
                    break

                if target.state == APState.DISCOVERED:
                    log.info("Starting capture: %s", target.ap.bssid)
                    cap_path = Path(cfg.paths.captures) / f"{target.ap.bssid.replace(':', '_')}.pcapng"
                    active_capture = CaptureSession(
                        monitor.monitor_iface, target.ap.bssid, target.ap.channel, cap_path
                    )
                    active_capture.start()
                    target.handshake_path = cap_path
                    scheduler.transition(target, SchedulerEvent.CLIENTS_PRESENT)

                elif target.state == APState.CAPTURING:
                    if active_capture and active_capture.handshake_detected():
                        log.info("Handshake found: %s", target.ap.bssid)
                        active_capture.stop()
                        active_capture = None
                        scheduler.transition(target, SchedulerEvent.CAPTURE_SUCCESS)
                    else:
                        log.debug("No handshake yet: %s", target.ap.bssid)

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
                    if cfg.cracking.enabled and target.hash_path:
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
        if active_capture:
            active_capture.stop()
        monitor.disable()
        save_raw(cfg.paths.state, state.targets)
        log.info("State saved. Exiting.")

if __name__ == "__main__":
    main()
