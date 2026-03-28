"""General Windows registry hive parser.

Walks a full registry hive using the ``Registry`` library, extracts all
keys and values, and stores notable entries as events.  Also provides a
targeted function that extracts only known persistence-related keys.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import tempfile
from typing import Any

import zstandard
from Registry import Registry

log = logging.getLogger("pickaxe.parser.registry")

_BATCH_SIZE = 500

# Well-known persistence-related registry key paths (case-insensitive
# substring matches against the full key path).
_PERSISTENCE_PATHS: list[str] = [
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved",
    "\\Software\\Microsoft\\Active Setup\\Installed Components",
    "\\System\\CurrentControlSet\\Services",
    "\\System\\CurrentControlSet\\Control\\Session Manager",
    "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
    "\\Software\\Classes\\CLSID",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
    "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
    "\\Environment",
]


def _decompress_blob(blob_path: str) -> str:
    """Decompress a zstd blob to a temp file; return path (or original)."""
    with open(blob_path, "rb") as fh:
        magic = fh.read(4)
    if magic != b"\x28\xb5\x2f\xfd":
        return blob_path
    dctx = zstandard.ZstdDecompressor()
    tmp = tempfile.NamedTemporaryFile(suffix=".hve", delete=False)
    try:
        with open(blob_path, "rb") as ifh, tmp:
            dctx.copy_stream(ifh, tmp)
    except Exception:
        os.unlink(tmp.name)
        raise
    return tmp.name


def _value_to_str(val: Any) -> str:
    """Convert a Registry value to a human-readable string."""
    try:
        v = val.value()
        if isinstance(v, bytes):
            # Show first 200 bytes as hex.
            return v[:200].hex()
        if isinstance(v, list):
            return "; ".join(str(x) for x in v)
        return str(v)
    except Exception:
        return "<error reading value>"


def _walk_key(
    key: Registry.RegistryKey,
    artifact_id: str,
    case_id: str,
    path_filter: list[str] | None = None,
) -> list[tuple]:
    """Recursively walk a registry key and yield event tuples.

    If *path_filter* is provided, only keys whose path contains one of the
    filter substrings (case-insensitive) will be emitted.
    """
    rows: list[tuple] = []
    stack: list[Registry.RegistryKey] = [key]

    while stack:
        current = stack.pop()
        try:
            key_path = current.path()
            key_ts = current.timestamp().isoformat() if current.timestamp() else ""
        except Exception:
            continue

        # Decide whether to emit this key.
        emit = True
        if path_filter:
            path_lower = key_path.lower()
            emit = any(p.lower() in path_lower for p in path_filter)

        if emit:
            # Collect values under this key.
            values_summary: dict[str, str] = {}
            try:
                for val in current.values():
                    try:
                        values_summary[val.name()] = _value_to_str(val)
                    except Exception:
                        values_summary[val.name()] = "<error>"
            except Exception:
                pass

            detail = f"Key={key_path}"
            if values_summary:
                # Truncate to keep detail under a reasonable size.
                vals_str = json.dumps(values_summary, default=str)
                if len(vals_str) > 2000:
                    vals_str = vals_str[:2000] + "..."
                detail += f" Values={vals_str}"

            raw = json.dumps({
                "key": key_path,
                "timestamp": key_ts,
                "values": values_summary,
            }, default=str)

            rows.append((
                case_id,
                artifact_id,
                key_ts,
                "registry",
                0,
                "Information",
                "",
                "Registry",
                "",
                detail,
                raw,
            ))

        # Recurse into sub-keys.
        try:
            for sub in current.subkeys():
                stack.append(sub)
        except Exception:
            pass

    return rows


def _insert_rows(conn: sqlite3.Connection, rows: list[tuple]) -> int:
    """Batch-insert rows into the events table. Returns count inserted."""
    total = 0
    for i in range(0, len(rows), _BATCH_SIZE):
        batch = rows[i : i + _BATCH_SIZE]
        conn.executemany(
            """
            INSERT INTO events
                (case_id, artifact_id, timestamp, source, event_id, level,
                 channel, provider, computer, message, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            batch,
        )
        conn.commit()
        total += len(batch)
    return total


def parse_registry_hive(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
) -> int:
    """Parse a full registry hive file and store all keys as events.

    Parameters
    ----------
    artifact_id:
        Unique identifier of the artifact.
    case_id:
        Parent case identifier.
    blob_path:
        Path to the (possibly zstd-compressed) hive file.
    db_path:
        Path to the Pickaxe SQLite database.

    Returns
    -------
    int
        Number of events inserted.
    """
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path)
    cleanup = decompressed != blob_path

    try:
        reg = Registry.Registry(decompressed)
        rows = _walk_key(reg.root(), artifact_id, case_id, path_filter=None)

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.commit()
        total = _insert_rows(conn, rows)
        conn.close()
    finally:
        if cleanup:
            os.unlink(decompressed)

    log.info("Parsed %d registry keys from artifact %s", total, artifact_id)
    return total


def extract_persistence_keys(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
) -> int:
    """Extract only known persistence-related keys from a registry hive.

    This is a faster, targeted alternative to :func:`parse_registry_hive`
    that focuses on keys commonly abused for persistence.

    Parameters
    ----------
    artifact_id:
        Unique identifier of the artifact.
    case_id:
        Parent case identifier.
    blob_path:
        Path to the (possibly zstd-compressed) hive file.
    db_path:
        Path to the Pickaxe SQLite database.

    Returns
    -------
    int
        Number of persistence-related events inserted.
    """
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path)
    cleanup = decompressed != blob_path

    try:
        reg = Registry.Registry(decompressed)
        rows = _walk_key(
            reg.root(), artifact_id, case_id,
            path_filter=_PERSISTENCE_PATHS,
        )

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.commit()
        total = _insert_rows(conn, rows)
        conn.close()
    finally:
        if cleanup:
            os.unlink(decompressed)

    log.info(
        "Extracted %d persistence-related registry keys from artifact %s",
        total, artifact_id,
    )
    return total
