"""ShimCache (AppCompatCache) parser.

Parses the binary AppCompatCache data that Windows stores in the SYSTEM
registry hive under:

    HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache

The binary format varies by Windows version.  This parser handles:

  - Windows 10+ (signature 0x30 / "10ts")
  - Windows 8.1 / 8  (signature 0x80 / "00ts")
  - Windows 7       (signature 0xBADC0FEE)
  - Windows XP      (signature 0xDEADBEEF)

Each entry contains a file path, a last-modified timestamp, and flags.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any

import zstandard

log = logging.getLogger("artifex.parser.shimcache")

_BATCH_SIZE = 500
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _decompress_blob(blob_path: str) -> str:
    """Decompress a zstd blob to a temp file; return path (or original)."""
    with open(blob_path, "rb") as fh:
        magic = fh.read(4)
    if magic != b"\x28\xb5\x2f\xfd":
        return blob_path
    dctx = zstandard.ZstdDecompressor()
    tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    try:
        with open(blob_path, "rb") as ifh, tmp:
            dctx.copy_stream(ifh, tmp)
    except Exception:
        os.unlink(tmp.name)
        raise
    return tmp.name


def _filetime_to_iso(filetime: int) -> str:
    """Convert Windows FILETIME to ISO-8601 string."""
    if filetime <= 0:
        return ""
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
        return dt.isoformat()
    except (OverflowError, OSError):
        return ""


def _parse_win10(data: bytes, offset: int) -> list[dict[str, Any]]:
    """Parse Windows 10+ ShimCache entries.

    Format per entry:
      - Signature "10ts" (4 bytes)
      - Unknown (4 bytes)
      - Cache entry size (4 bytes)
      - Path size (2 bytes)
      - Path (UTF-16LE, variable)
      - Last modified FILETIME (8 bytes)
      - Data size (4 bytes)
      - Data (variable)
    """
    entries: list[dict[str, Any]] = []
    pos = offset

    while pos < len(data) - 12:
        # Look for "10ts" signature.
        sig = data[pos:pos + 4]
        if sig != b"10ts":
            break

        try:
            _unknown = struct.unpack_from("<I", data, pos + 4)[0]
            entry_size = struct.unpack_from("<I", data, pos + 8)[0]
            path_size = struct.unpack_from("<H", data, pos + 12)[0]

            path_start = pos + 14
            path_end = path_start + path_size
            if path_end > len(data):
                break

            file_path = data[path_start:path_end].decode("utf-16-le", errors="replace").rstrip("\x00")

            ft_offset = path_end
            if ft_offset + 8 > len(data):
                break
            filetime = struct.unpack_from("<Q", data, ft_offset)[0]
            modified = _filetime_to_iso(filetime)

            data_size_offset = ft_offset + 8
            data_size = 0
            if data_size_offset + 4 <= len(data):
                data_size = struct.unpack_from("<I", data, data_size_offset)[0]

            entries.append({
                "file_path": file_path,
                "last_modified": modified,
                "exec_flag": "",
                "data_size": data_size,
            })

            # Advance to next entry.
            pos += entry_size + 12
        except (struct.error, UnicodeDecodeError):
            log.debug("ShimCache parse error at offset %d; stopping", pos)
            break

    return entries


def _parse_win7(data: bytes, offset: int) -> list[dict[str, Any]]:
    """Parse Windows 7 ShimCache entries.

    Format per entry:
      - Path size (2 bytes)
      - Max path size (2 bytes)
      - Padding (4 bytes on 64-bit)
      - Path pointer (4/8 bytes)
      - Last modified FILETIME (8 bytes)
      - Flags (4 bytes)
      - Shim flags (4 bytes)
      - Data size (4 bytes)
      - Data pointer (4/8 bytes)
    """
    entries: list[dict[str, Any]] = []
    pos = offset

    # Determine 32 vs 64 bit from header.
    if len(data) < 4:
        return entries

    num_entries = struct.unpack_from("<I", data, 4)[0]

    for _ in range(min(num_entries, 10000)):
        if pos + 48 > len(data):
            break
        try:
            path_size = struct.unpack_from("<H", data, pos)[0]
            _max_path = struct.unpack_from("<H", data, pos + 2)[0]
            # Skip 4 bytes padding.
            # Path offset (pointer -- not useful for raw data, path follows inline in some variants).
            # For simplicity, try to read inline path.
            path_start = pos + 8
            path_end = path_start + path_size
            if path_end > len(data):
                break

            file_path = data[path_start:path_end].decode("utf-16-le", errors="replace").rstrip("\x00")

            ft_offset = path_end
            if ft_offset + 8 > len(data):
                break
            filetime = struct.unpack_from("<Q", data, ft_offset)[0]
            modified = _filetime_to_iso(filetime)

            flags_offset = ft_offset + 8
            flags = 0
            if flags_offset + 4 <= len(data):
                flags = struct.unpack_from("<I", data, flags_offset)[0]

            exec_flag = "yes" if flags & 0x02 else "no"

            entries.append({
                "file_path": file_path,
                "last_modified": modified,
                "exec_flag": exec_flag,
                "data_size": 0,
            })

            # Rough entry size estimate.
            pos = flags_offset + 8 + 4
        except (struct.error, UnicodeDecodeError):
            break

    return entries


def _parse_entries(data: bytes) -> list[dict[str, Any]]:
    """Detect the ShimCache format and parse entries accordingly."""
    if len(data) < 8:
        log.warning("ShimCache data too short (%d bytes)", len(data))
        return []

    sig = struct.unpack_from("<I", data, 0)[0]

    # Windows 10+: header is 0x30 bytes, entries start after.
    if sig == 0x30:
        return _parse_win10(data, 0x30)

    # Windows 8/8.1: header is 0x80 bytes.
    if sig == 0x80:
        return _parse_win10(data, 0x80)

    # Windows 7: signature 0xBADC0FEE.
    if sig == 0xBADC0FEE:
        return _parse_win7(data, 0x80)

    # Windows XP: signature 0xDEADBEEF.
    if sig == 0xDEADBEEF:
        # XP format is significantly different; extract what we can.
        log.info("Windows XP ShimCache detected; limited parsing support")
        return _parse_win7(data, 0x190)

    # Try to detect "10ts" entries anywhere in the data.
    marker = data.find(b"10ts")
    if marker != -1:
        log.info("Found 10ts marker at offset %d; attempting parse", marker)
        return _parse_win10(data, marker)

    log.warning("Unknown ShimCache signature: 0x%08X", sig)
    return []


def parse_shimcache(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
) -> int:
    """Parse ShimCache binary data and store events.

    Parameters
    ----------
    artifact_id:
        Unique identifier of the artifact.
    case_id:
        Parent case identifier.
    blob_path:
        Path to the (possibly zstd-compressed) ShimCache binary data.
    db_path:
        Path to the Artifex SQLite database.

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
        with open(decompressed, "rb") as fh:
            data = fh.read()

        entries = _parse_entries(data)
        if not entries:
            log.info("No ShimCache entries found in artifact %s", artifact_id)
            return 0

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.commit()
        batch: list[tuple] = []

        for idx, entry in enumerate(entries):
            file_path = entry.get("file_path", "")
            modified = entry.get("last_modified", "")
            exec_flag = entry.get("exec_flag", "")

            raw = json.dumps(entry, default=str)
            message = (
                f"ShimCache entry for {file_path or 'unknown file'} "
                f"(modified {modified or 'unknown'}, execution flag {exec_flag or 'unknown'})."
            )

            batch.append((
                case_id,
                artifact_id,
                modified,
                "shimcache",
                0,
                "Information",
                "",
                "ShimCache",
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

    log.info("Parsed %d ShimCache entries from artifact %s", total, artifact_id)
    return total
