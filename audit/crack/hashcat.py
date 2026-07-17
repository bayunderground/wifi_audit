from __future__ import annotations
import re
from ..logging import get_logger
from ..util.subprocess import run, CommandError

log = get_logger(__name__)

class HashcatError(Exception):
    pass

def crack(hash_file: str, mask: str, custom_charsets: dict[int, str] | None = None, potfile: str | None = None) -> str | None:
    log.info("Cracking %s with mask %s", hash_file, mask)
    cmd = ["hashcat", "-m", "22000", hash_file]
    if custom_charsets:
        cmd.extend(["-a", "3"])
        for idx, charset in sorted(custom_charsets.items()):
            cmd.extend([f"-{idx}", charset])
    if potfile is not None:
        cmd.extend(["--potfile-path", potfile])
    cmd.append(mask)
    try:
        output = run(cmd)
    except CommandError as e:
        raise HashcatError(f"hashcat failed: {e.stderr}") from e
    match = re.search(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}:([^\s]+)", output, re.MULTILINE | re.IGNORECASE)
    if match:
        password = match.group(2)
        log.info("Password found: %s", password)
        return password
    log.info("Password not found")
    return None
