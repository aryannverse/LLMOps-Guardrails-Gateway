"""Append-only, tamper-evident JSONL audit log.

Every record stores the SHA-256 hash of the previous record (a hash chain, as in
certificate-transparency logs). Editing or deleting any earlier line breaks the
chain, which verify_chain() and the dashboard detect.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class TelemetryLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev = GENESIS
        if self.path.exists():  # resume the chain after a restart
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._prev = json.loads(line)["hash"]

    def append(self, record: dict) -> dict:
        with self._lock:
            entry = {**record, "prev_hash": self._prev}
            entry["hash"] = _digest(self._prev, entry)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._prev = entry["hash"]
            return entry


def verify_chain(path: str | Path) -> tuple[bool, int, int]:
    """Return (is_intact, records_checked, first_bad_line_index or -1)."""
    prev, n = GENESIS, 0
    p = Path(path)
    if not p.exists():
        return True, 0, -1
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, n, i
        stored = entry.pop("hash", None)
        if entry.get("prev_hash") != prev or _digest(prev, entry) != stored:
            return False, n, i
        prev, n = stored, n + 1
    return True, n, -1
