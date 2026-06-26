# Implementation Plan

8 TODOs across 4 files + 2 stub modules + 1 stub utility.

---

## Phase 1 — Subprocess Wrapper (foundation)

All capture/crack modules need to shell out to external tools. CLAUDE.md says: never call subprocess directly from business logic.

**File:** `audit/util/subprocess.py`

- [ ] `run(cmd: list[str], timeout: int | None = None) -> str` — runs a command, returns stdout, raises `CommandError` on non-zero exit
- [ ] `CommandError` — domain exception with `cmd`, `returncode`, `stderr` fields
- [ ] Tests in `tests/test_subprocess.py` — mock `subprocess.run`, test success and failure paths

---

## Phase 2 — Monitor Manager

**File:** `audit/capture/monitor.py`

Uses `iw` and `airmon-ng` via the subprocess wrapper.

- [ ] `enable()` — `airmon-ng start <interface>`, sets `self._monitor_iface`
- [ ] `disable()` — `airmon-ng stop <monitor_iface>`
- [ ] `set_channel(channel)` — `iw dev <monitor_iface> set channel <channel>`
- [ ] Tests in `tests/test_monitor.py` — mock subprocess, verify correct commands

---

## Phase 3 — Capture Session (hcxdumptool)

**File:** `audit/capture/hcxdump.py`

- [ ] `start()` — spawn `hcxdumptool -i <monitor_iface> --bssid <bssid> --channel <channel> -w <capture_path>` as background process
- [ ] `stop()` — terminate background process gracefully
- [ ] `handshake_detected()` — check capture file for valid handshake using hcxpcapngtool `--all` output
- [ ] Tests in `tests/test_hcxdump.py` — mock subprocess, test start/stop/detect lifecycle

Requires: Phase 1 (subprocess wrapper), Phase 2 (monitor manager provides interface)

---

## Phase 4 — Verification

**File:** `audit/capture/verifier.py`

- [ ] `verify_capture(capture_file) -> bool` — run `hcxpcapngtool <file>`, parse output for PMKID or EAPOL count, return True if at least one valid hash exists
- [ ] Tests in `tests/test_verifier.py` — mock subprocess, test valid/invalid capture output

Requires: Phase 1

---

## Phase 5 — Converter

**File:** `audit/capture/converter.py`

- [ ] `convert_to_22000(capture_file, output_file)` — run `hcxpcapngtool -o <output_file> <capture_file>`, raise `ConversionError` on failure
- [ ] Tests in `tests/test_converter.py` — mock subprocess, test success and failure

Requires: Phase 1

---

## Phase 6 — Hashcat Wrapper

**File:** `audit/crack/hashcat.py`

- [ ] `crack(hash_file: str, mask: str) -> str | None` — run `hashcat -m 22000 <hash_file> <mask>`, parse output for recovered password, return password or None
- [ ] `HashcatError` exception
- [ ] Tests in `tests/test_hashcat.py` — mock subprocess, test cracked/not-cracked/error paths

Requires: Phase 1

---

## Phase 7 — Reporter

**File:** `audit/report/report.py`

- [ ] `generate_report(state: AuditState, output_dir: Path) -> Path` — iterate targets, write ESSID/BSSID/PASSWORD (or status), return report path
- [ ] Tests in `tests/test_report.py` — test with mixed cracked/uncracked targets

Requires: Phase 1 (none, just models)

---

## Phase 8 — Main Loop Integration

**File:** `main.py`

Wire everything together:

- [ ] Parse CLI args (config path, optional filters)
- [ ] Initialize monitor manager, scanner, capture, verifier, converter, cracker, reporter
- [ ] Run scheduler loop: scan -> capture -> verify -> convert -> crack -> report
- [ ] Graceful shutdown on SIGINT, persist state

---

## Execution Order

```
1. subprocess wrapper  (no dependencies)
2. monitor manager     (depends on 1)
3. capture session     (depends on 1, 2)
4. verifier            (depends on 1)
5. converter           (depends on 1)
6. hashcat wrapper     (depends on 1)
7. reporter            (no external deps)
8. main loop           (depends on all above)
```

Phases 2-7 can be parallelized where independent.
