"""Windows Prefetch (.pf) file parser.

Handles the binary Prefetch format for Windows versions XP through 11.
Decompresses zstd blobs, extracts execution metadata, and inserts
normalised events into the Pickaxe ``events`` table.

Reference structure (simplified):
  Offset 0x00  - Signature / version (4 bytes)
  Offset 0x04  - Signature "SCCA" (4 bytes)
  Offset 0x0C  - File size (4 bytes)
  Offset 0x10  - Executable name (60 bytes, UTF-16LE, null-padded)
  Offset 0x4C  - Prefetch hash (4 bytes)
  Run count and last-run timestamps vary by version.
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

log = logging.getLogger("pickaxe.parser.prefetch")

# Prefetch format versions.
_VER_XP = 17       # Windows XP / 2003
_VER_VISTA = 23    # Windows Vista / 7
_VER_WIN8 = 26     # Windows 8 / 8.1
_VER_WIN10 = 30    # Windows 10 / 11

# Batch insert size.
_BATCH_SIZE = 200

# Windows FILETIME epoch: 1601-01-01.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _decompress_blob(blob_path: str) -> str:
    """Decompress a zstd blob to a temp file; return path (or original)."""
    with open(blob_path, "rb") as fh:
        magic = fh.read(4)
    if magic != b"\x28\xb5\x2f\xfd":
        return blob_path
    dctx = zstandard.ZstdDecompressor()
    tmp = tempfile.NamedTemporaryFile(suffix=".pf", delete=False)
    try:
        with open(blob_path, "rb") as ifh, tmp:
            dctx.copy_stream(ifh, tmp)
    except Exception:
        os.unlink(tmp.name)
        raise
    return tmp.name


def _filetime_to_iso(filetime: int) -> str:
    """Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to ISO-8601."""
    if filetime <= 0:
        return ""
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
        return dt.isoformat()
    except (OverflowError, OSError):
        return ""


def _parse_pf_data(data: bytes) -> dict[str, Any] | None:
    """Parse raw prefetch bytes and return extracted metadata.

    Returns ``None`` if the data is not a valid Prefetch file.
    """
    if len(data) < 0x60:
        log.warning("Prefetch data too short (%d bytes)", len(data))
        return None

    version = struct.unpack_from("<I", data, 0x00)[0]
    signature = data[0x04:0x08]
    if signature != b"SCCA":
        log.warning("Invalid prefetch signature: %r", signature)
        return None

    file_size = struct.unpack_from("<I", data, 0x0C)[0]

    # Executable name: 60 bytes of UTF-16LE starting at offset 0x10.
    exe_name_raw = data[0x10:0x4C]
    try:
        exe_name = exe_name_raw.decode("utf-16-le").split("\x00", 1)[0]
    except UnicodeDecodeError:
        exe_name = ""

    pf_hash = struct.unpack_from("<I", data, 0x4C)[0]

    # Run count and last-run timestamps depend on version.
    run_count = 0
    last_run_times: list[str] = []

    try:
        if version == _VER_XP:
            # Run count at 0x90, last run time at 0x78 (single FILETIME).
            run_count = struct.unpack_from("<I", data, 0x90)[0]
            ft = struct.unpack_from("<Q", data, 0x78)[0]
            ts = _filetime_to_iso(ft)
            if ts:
                last_run_times.append(ts)

        elif version == _VER_VISTA:
            # Run count at 0x98, last run time at 0x80.
            run_count = struct.unpack_from("<I", data, 0x98)[0]
            ft = struct.unpack_from("<Q", data, 0x80)[0]
            ts = _filetime_to_iso(ft)
            if ts:
                last_run_times.append(ts)

        elif version in (_VER_WIN8, _VER_WIN10):
            # Run count at 0xD0, up to 8 last-run times starting at 0x80.
            run_count = struct.unpack_from("<I", data, 0xD0)[0]
            for i in range(8):
                offset = 0x80 + i * 8
                if offset + 8 > len(data):
                    break
                ft = struct.unpack_from("<Q", data, offset)[0]
                ts = _filetime_to_iso(ft)
                if ts:
                    last_run_times.append(ts)

        else:
            log.info("Unknown prefetch version %d; extracting basic info only", version)
    except struct.error:
        log.warning("Struct unpack error while parsing prefetch version %d", version)

    return {
        "version": version,
        "file_size": file_size,
        "executable": exe_name,
        "prefetch_hash": f"0x{pf_hash:08X}",
        "run_count": run_count,
        "last_run_times": last_run_times,
    }


def parse_prefetch(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
) -> int:
    """Parse a Windows Prefetch file and store events.

    Parameters
    ----------
    artifact_id:
        Unique identifier of the artifact.
    case_id:
        Parent case identifier.
    blob_path:
        Path to the (possibly zstd-compressed) .pf file.
    db_path:
        Path to the Pickaxe SQLite database.

    Returns
    -------
    int
        Number of events inserted (one per last-run timestamp, minimum 1).
    """
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path)
    cleanup = decompressed != blob_path
    total = 0

    try:
        with open(decompressed, "rb") as fh:
            data = fh.read()

        parsed = _parse_pf_data(data)
        if parsed is None:
            log.warning("Could not parse prefetch file for artifact %s", artifact_id)
            return 0

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.commit()
        rows: list[tuple] = []

        # Create one event per last-run timestamp so each execution appears
        # in the timeline.  If there are no timestamps, insert a single
        # summary event with an empty timestamp.
        timestamps = parsed["last_run_times"] if parsed["last_run_times"] else [""]

        for ts in timestamps:
            raw = json.dumps(parsed, default=str)
            message = (
                f"Executable {parsed['executable']} ran "
                f"{parsed['run_count']} times (prefetch hash {parsed['prefetch_hash']})."
            )

            rows.append((
                case_id,
                artifact_id,
                ts,
                "prefetch",
                0,
                "Information",
                "",
                "Prefetch",
                "",
                message,
                raw,
            ))

        conn.executemany(
            """
            INSERT INTO events
                (case_id, artifact_id, timestamp, source, event_id, level,
                 channel, provider, computer, message, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        total = len(rows)

        conn.close()
    finally:
        if cleanup:
            os.unlink(decompressed)

    log.info(
        "Parsed prefetch for artifact %s: exe=%s run_count=%d events=%d",
        artifact_id,
        parsed.get("executable", "?"),
        parsed.get("run_count", 0),
        total,
    )
    return total
