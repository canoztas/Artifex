"""Windows Prefetch (.pf) file parser.

Handles the binary Prefetch format for Windows versions XP through 11.
Decompresses zstd blobs, extracts execution metadata, and inserts
normalised events into the Artifex ``events`` table.

Reference structure (simplified):
  Offset 0x00  - Signature / version (4 bytes)
  Offset 0x04  - Signature "SCCA" (4 bytes)
  Offset 0x0C  - File size (4 bytes)
  Offset 0x10  - Executable name (60 bytes, UTF-16LE, null-padded)
  Offset 0x4C  - Prefetch hash (4 bytes)
  Run count and last-run timestamps vary by version.
"""

from __future__ import annotations

import ctypes
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

log = logging.getLogger("artifex.parser.prefetch")

# Prefetch format versions.
_VER_XP = 17       # Windows XP / 2003
_VER_VISTA = 23    # Windows Vista / 7
_VER_WIN8 = 26     # Windows 8 / 8.1
_VER_WIN10 = 30    # Windows 10 / 11

# Batch insert size.
_BATCH_SIZE = 200

# Windows FILETIME epoch: 1601-01-01.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Windows 8+ compressed Prefetch files use an internal "MAM" wrapper.
_MAM_SIGNATURE = 0x004D414D
_MAM_SIGNATURE_MASK = 0x00FFFFFF
_COMPRESSION_FORMAT_LZNT1 = 0x0002
_COMPRESSION_FORMAT_XPRESS = 0x0003
_COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004


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


def _decompress_windows_prefetch(data: bytes) -> bytes:
    """Expand a Windows-compressed Prefetch payload if needed."""
    if len(data) < 8:
        return data

    signature = struct.unpack_from("<I", data, 0)[0]
    if signature & _MAM_SIGNATURE_MASK != _MAM_SIGNATURE:
        return data

    if os.name != "nt":
        raise RuntimeError("compressed Windows Prefetch files require Windows decompression support")

    compression_format = (signature >> 24) & 0x0F
    has_checksum = (signature >> 28) & 0x0F
    if compression_format not in {
        _COMPRESSION_FORMAT_LZNT1,
        _COMPRESSION_FORMAT_XPRESS,
        _COMPRESSION_FORMAT_XPRESS_HUFF,
    }:
        raise RuntimeError(f"unsupported Prefetch compression format: {compression_format}")

    decompressed_size = struct.unpack_from("<I", data, 4)[0]
    payload_offset = 12 if has_checksum else 8
    compressed = data[payload_offset:]
    if not compressed:
        raise RuntimeError("compressed Prefetch payload is empty")

    ntdll = ctypes.WinDLL("ntdll")
    get_workspace_size = ntdll.RtlGetCompressionWorkSpaceSize
    get_workspace_size.argtypes = [
        ctypes.c_ushort,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    get_workspace_size.restype = ctypes.c_long

    decompress = ntdll.RtlDecompressBufferEx
    decompress.argtypes = [
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_void_p,
    ]
    decompress.restype = ctypes.c_long

    workspace_size = ctypes.c_ulong()
    fragment_size = ctypes.c_ulong()
    status = get_workspace_size(
        compression_format,
        ctypes.byref(workspace_size),
        ctypes.byref(fragment_size),
    )
    if status != 0:
        raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status & 0xFFFFFFFF:08X}")

    output = ctypes.create_string_buffer(decompressed_size)
    compressed_buffer = ctypes.create_string_buffer(compressed, len(compressed))
    final_size = ctypes.c_ulong()
    workspace = ctypes.create_string_buffer(workspace_size.value)

    status = decompress(
        compression_format,
        output,
        decompressed_size,
        compressed_buffer,
        len(compressed),
        ctypes.byref(final_size),
        workspace,
    )
    if status != 0:
        raise RuntimeError(f"RtlDecompressBufferEx failed: 0x{status & 0xFFFFFFFF:08X}")

    return output.raw[:final_size.value]


def _parse_pf_data(data: bytes) -> dict[str, Any] | None:
    """Parse raw prefetch bytes and return extracted metadata.

    Returns ``None`` if the data is not a valid Prefetch file.
    """
    try:
        data = _decompress_windows_prefetch(data)
    except Exception as exc:
        log.warning("Failed to decompress Windows Prefetch payload: %s", exc)
        return None

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
        Path to the Artifex SQLite database.

    Returns
    -------
    int
        Number of events inserted (one per stored last-run timestamp, minimum 1).
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

        # Create one event per stored last-run timestamp so each recorded
        # Prefetch timestamp appears in the timeline. If there are no
        # timestamps, insert a single summary event with an empty timestamp.
        timestamps = parsed["last_run_times"] if parsed["last_run_times"] else [""]
        total_timestamps = len(parsed["last_run_times"])

        for index, ts in enumerate(timestamps, start=1):
            event_data = {
                **parsed,
                "observed_timestamp": ts,
                "observed_timestamp_index": index if ts else 0,
                "observed_timestamp_total": total_timestamps,
            }
            raw = json.dumps(event_data, default=str)

            if ts:
                message = (
                    f"Prefetch recorded {parsed['executable']} with a recent execution "
                    f"timestamp (slot {index} of {total_timestamps}; recorded run count "
                    f"field {parsed['run_count']}; prefetch hash {parsed['prefetch_hash']})."
                )
            else:
                message = (
                    f"Prefetch recorded {parsed['executable']}, but no recent execution "
                    f"timestamps were present (recorded run count field "
                    f"{parsed['run_count']}; prefetch hash {parsed['prefetch_hash']})."
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
