from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from ..models import AuditState, APState
from ..logging import get_logger

log = get_logger(__name__)

def generate_report(state: AuditState, output_dir: Path) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"report_{ts}.txt"
    lines = []
    for bssid, target in state.targets.items():
        lines.append(target.ap.essid)
        lines.append(bssid)
        if target.state == APState.CRACKED and target.password:
            lines.append(target.password)
        elif target.handshake_path:
            lines.append("not found")
        else:
            lines.append("no handshake")
        lines.append("")
    path.write_text("\n".join(lines))
    log.info("Report written to %s", path)
    return path
