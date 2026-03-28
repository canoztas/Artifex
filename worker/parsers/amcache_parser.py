"""AmCache.hve parser.

Parses a Windows AmCache registry hive to extract application-execution
artifacts.  The primary key of interest is:

    Root\\InventoryApplicationFile

Each sub-key contains metadata about a file that was seen by the system:
file path, SHA-1 hash, file size, link date, publisher, version, etc.

Uses the ``Registry`` library to walk the hive.
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

log = logging.getLogger("pickaxe.parser.amcache")

_BATCH_SIZE = 500

# Registry value names of interest under each InventoryApplicationFile sub-key.
_VALUE_MAP: dict[str, str] = {
    "LowerCaseLongPath": "file_path",
    "FileId": "sha1",
    "Size": "file_size",
    "LinkDate": "link_date",
    "Publisher": "publisher",
    "Version": "version",
    "BinFileVersion": "bin_file_version",
    "ProductName": "product_name",
    "Name": "name",
    "ProgramId": "program_id",
    "Language": "language",
}


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


def _safe_value(key: Registry.RegistryKey, name: str) -> str:
    """Return the string value for *name* or empty string if absent."""
    try:
        return str(key.value(name).value())
    except Registry.RegistryValueNotFoundException:
        return ""
    except Exception:
        return ""


def _extract_entries(reg: Registry.Registry) -> list[dict[str, Any]]:
    """Walk InventoryApplicationFile and extract entries."""
    entries: list[dict[str, Any]] = []

    try:
        inv_key = reg.open("Root\\InventoryApplicationFile")
    except Registry.RegistryKeyNotFoundException:
        log.info("InventoryApplicationFile key not found; trying alternate paths")
        # Older AmCache versions use Root\\File\\{volume_guid}
        try:
            root = reg.open("Root\\File")
        except Registry.RegistryKeyNotFoundException:
            log.warning("No known AmCache key structure found in hive")
            return entries

        for vol_key in root.subkeys():
            for file_key in vol_key.subkeys():
                entry: dict[str, Any] = {"_key": file_key.path()}
                for val in file_key.values():
                    entry[val.name()] = str(val.value())
                entries.append(entry)
        return entries

    for sub in inv_key.subkeys():
        entry: dict[str, Any] = {}
        for reg_name, field_name in _VALUE_MAP.items():
            entry[field_name] = _safe_value(sub, reg_name)
        entry["_key"] = sub.path()
        entries.append(entry)

    return entries


def parse_amcache(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
) -> int:
    """Parse an AmCache.hve and store execution artifacts as events.

    Parameters
    ----------
    artifact_id:
        Unique identifier of the artifact.
    case_id:
        Parent case identifier.
    blob_path:
        Path to the (possibly zstd-compressed) AmCache hive on disk.
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
    total = 0

    try:
        reg = Registry.Registry(decompressed)
        entries = _extract_entries(reg)
        if not entries:
            log.info("No AmCache entries found in artifact %s", artifact_id)
            return 0

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.commit()
        batch: list[tuple] = []

        for entry in entries:
            file_path = entry.get("file_path", entry.get("_key", ""))
            sha1 = entry.get("sha1", "")
            link_date = entry.get("link_date", "")
            timestamp = link_date if link_date else ""

            raw = json.dumps(entry, default=str)
            message = (
                f"AmCache recorded {file_path or 'unknown file'} "
                f"(publisher {entry.get('publisher', 'unknown')}, version {entry.get('version', 'unknown')})."
            )

            batch.append((
                case_id,
                artifact_id,
                timestamp,
                "amcache",
                0,
                "Information",
                "",
                "AmCache",
                "",
                message,
                raw,
            ))

            if len(batch) >= _BATCH_SIZE:
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
                batch.clear()

        if batch:
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

        conn.close()
    finally:
        if cleanup:
            os.unlink(decompressed)

    log.info("Parsed %d AmCache entries from artifact %s", total, artifact_id)
    return total
