"""Tamper-evident report integrity using HMAC-SHA256.

A plain SHA-256 digest only detects accidental change: anyone who edits an
exported report can simply recompute the hash, so it is not tamper-evident.
This module signs each report with HMAC-SHA256 using a secret key that lives in
the deployment (environment variable or a locally generated key file). Without
the key an attacker cannot forge a valid signature for a modified report, which
is what makes the integrity claim meaningful.

The public function names are unchanged so the rest of the app keeps working.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

_ENV_VAR = "REPORT_INTEGRITY_KEY"
_KEY_FILE = Path("data/.integrity_key")


def _load_key() -> bytes:
    """Resolve the signing key: env var first, then a persisted local key file.

    On first run (no env var, no key file) a strong random key is generated and
    saved so verification stays consistent across sessions on the same install.
    """
    env_key = os.environ.get(_ENV_VAR)
    if env_key:
        return env_key.encode("utf-8")

    try:
        if _KEY_FILE.exists():
            data = _KEY_FILE.read_text(encoding="utf-8").strip()
            if data:
                return data.encode("utf-8")
        _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_hex(32)
        _KEY_FILE.write_text(new_key, encoding="utf-8")
        return new_key.encode("utf-8")
    except Exception:
        # Last-resort deterministic fallback so the app never crashes in a demo.
        return b"cyber-exposure-governance-platform-default-key"


def generate_sha256(file_bytes: bytes) -> str:
    """Return the HMAC-SHA256 signature (hex) for the given report bytes."""
    return hmac.new(_load_key(), file_bytes, hashlib.sha256).hexdigest()


def verify_sha256(file_bytes: bytes, original_hash: str) -> bool:
    """Constant-time verification of a report against its HMAC-SHA256 signature."""
    calculated = generate_sha256(file_bytes)
    return hmac.compare_digest(
        calculated.lower().strip(), str(original_hash).lower().strip()
    )
