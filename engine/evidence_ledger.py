"""Minimal append-only hash-chain ledger for tamper-evident demo receipts.

Only analysis identifiers and evidence hashes are written. Email content and PII
remain off-ledger. This demonstrates the integrity pattern without pretending to
be a production blockchain network.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict


class EvidenceLedger:
    _lock = threading.Lock()

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, analysis_id: str, evidence_hash: str) -> Dict[str, str]:
        with self._lock:
            previous_hash = self._last_hash()
            record = {
                "analysis_id": analysis_id,
                "evidence_hash": evidence_hash,
                "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                "previous_record_hash": previous_hash,
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
            record_hash = hashlib.sha256(canonical).hexdigest()
            record["record_hash"] = record_hash
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            return {
                "record_hash": record_hash,
                "previous_record_hash": previous_hash,
                "recorded_at_utc": record["recorded_at_utc"],
                "ledger_type": "LOCAL_APPEND_ONLY_HASH_CHAIN",
                "privacy": "Only identifiers and SHA-256 hashes are stored; message content remains off-ledger.",
            }

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        last = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return "GENESIS"
        try:
            return json.loads(last).get("record_hash", "GENESIS")
        except json.JSONDecodeError:
            return "INVALID_PREVIOUS_RECORD"
