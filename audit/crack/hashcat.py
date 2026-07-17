from __future__ import annotations
import re
from ..logging import get_logger
from ..util.subprocess import run, CommandError

log = get_logger(__name__)

class HashcatError(Exception):
    pass

def crack(hash_file: str, mask: str, custom_charsets: dict[int, str] | None = None, potfile: str | None = None) -> str | None:
    log.info("Cracking %s with mask %s", hash_file, mask)
    cmd = ["hashcat", "-m", "22000"]
    if potfile is not None:
        cmd.extend(["--potfile-path", potfile])
    if custom_charsets:
        cmd.extend(["-a", "3"])
        for idx, charset in sorted(custom_charsets.items()):
            cmd.extend([f"-{idx}", charset])
    cmd.extend([hash_file, mask])
    try:
        output = run(cmd)
    except CommandError as e:
        raise HashcatError(f"hashcat failed: {e.stderr}") from e
    match = re.search(r":([^:\s]+)\s*$", output, re.MULTILINE)
    if match:
        password = match.group(1)
        if "://" in password or password.startswith("//"):
            log.info("Ignoring URL in output: %s", password)
        else:
            log.info("Password found: %s", password)
            return password
    log.info("Password not found")
    return None
