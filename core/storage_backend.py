"""Pluggable storage backend: local filesystem (default) or Google Cloud Storage.

Cloud Storage is used **only** when the ``CEGP_GCS_BUCKET`` environment variable is
set, the ``google-cloud-storage`` package is importable, and the bucket is reachable.
In every other case this transparently falls back to the local filesystem with
identical behaviour. This keeps local runs completely unchanged while letting a
Cloud Run deployment persist data durably (see the GCP guide, Part 11).

Configuration (cloud only):
    CEGP_GCS_BUCKET   the bucket name to store data in (enables the GCS backend)
    CEGP_GCS_PREFIX   optional key prefix inside the bucket (e.g. "cegp")

The backend exposes a tiny, filesystem-like API used by the history archive:
    exists / read_text / write_text / read_bytes / write_bytes / delete
Paths are logical and relative (e.g. "runs/runs_index.csv").
"""
from __future__ import annotations

import os
from pathlib import Path

ENV_BUCKET = "CEGP_GCS_BUCKET"
ENV_PREFIX = "CEGP_GCS_PREFIX"

# Cache backends by configuration so we don't rebuild a GCS client on every call.
_CACHE: dict = {}


class LocalBackend:
    """Filesystem backend. Logical paths resolve relative to ``base``."""

    name = "local"

    def __init__(self, base: str | Path = "."):
        self.base = Path(base)

    def _p(self, path: str | Path) -> Path:
        path = Path(path)
        return path if path.is_absolute() else self.base / path

    def exists(self, path) -> bool:
        try:
            return self._p(path).exists()
        except Exception:
            return False

    def read_text(self, path) -> str | None:
        p = self._p(path)
        try:
            return p.read_text(encoding="utf-8") if p.exists() else None
        except Exception:
            return None

    def write_text(self, path, text: str) -> None:
        p = self._p(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def read_bytes(self, path) -> bytes | None:
        p = self._p(path)
        try:
            return p.read_bytes() if p.exists() else None
        except Exception:
            return None

    def write_bytes(self, path, data: bytes) -> None:
        p = self._p(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def delete(self, path) -> None:
        p = self._p(path)
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


class GCSBackend:
    """Google Cloud Storage backend. Logical paths become object keys under a prefix."""

    name = "gcs"

    def __init__(self, bucket_name: str, prefix: str = ""):
        from google.cloud import storage  # lazy import; only needed in the cloud
        self._client = storage.Client()
        self._bucket = self._client.bucket(bucket_name)
        self._prefix = (prefix or "").strip("/")

    def _key(self, path) -> str:
        rel = str(path).replace("\\", "/").lstrip("/")
        return f"{self._prefix}/{rel}" if self._prefix else rel

    def _blob(self, path):
        return self._bucket.blob(self._key(path))

    def exists(self, path) -> bool:
        try:
            return self._blob(path).exists()
        except Exception:
            return False

    def read_text(self, path) -> str | None:
        try:
            b = self._blob(path)
            return b.download_as_text() if b.exists() else None
        except Exception:
            return None

    def write_text(self, path, text: str) -> None:
        self._blob(path).upload_from_string(text, content_type="text/csv")

    def read_bytes(self, path) -> bytes | None:
        try:
            b = self._blob(path)
            return b.download_as_bytes() if b.exists() else None
        except Exception:
            return None

    def write_bytes(self, path, data: bytes) -> None:
        self._blob(path).upload_from_string(data)

    def delete(self, path) -> None:
        try:
            b = self._blob(path)
            if b.exists():
                b.delete()
        except Exception:
            pass


def get_backend(local_base: str | Path = "."):
    """Return the active backend: GCS when configured and reachable, else local.

    Never raises: any failure to construct the GCS backend falls back to local,
    so the app keeps working regardless of environment.
    """
    bucket = os.environ.get(ENV_BUCKET, "").strip()
    prefix = os.environ.get(ENV_PREFIX, "").strip()
    key = (bucket, prefix, str(local_base))
    if key in _CACHE:
        return _CACHE[key]

    backend = None
    if bucket:
        try:
            backend = GCSBackend(bucket, prefix)
            # Light reachability touch; returns False but exercises the client/creds.
            backend.exists("__cegp_healthcheck__")
        except Exception:
            backend = None  # fall back to local on any problem

    if backend is None:
        backend = LocalBackend(local_base)

    _CACHE[key] = backend
    return backend


def active_backend_name(local_base: str | Path = ".") -> str:
    """Return 'gcs' or 'local' for display in the UI."""
    try:
        return get_backend(local_base).name
    except Exception:
        return "local"
