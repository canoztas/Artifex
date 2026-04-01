"""Windows Defender log parser.

Parses text-based Defender support logs such as MPLog entries into the
Artifex ``events`` table. If the artifact is actually an EVTX file, the
caller should route it through the EVTX parser instead.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone

import zstandard

log = logging.getLogger("artifex.parser.defender")

_BATCH_SIZE = 500
_LOCAL_TZ = datetime.now().astimezone().tzinfo or timezone.utc
_TIMESTAMP_PATTERNS: list[tuple[re.Pattern[str], tuple[str, ...]]] = [
    (
        re.compile(r"^\s*\[?(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]?"),
        ("%Y-%m-%d %H:%M:%S",),
    ),
    (
        re.compile(r"^\s*(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"),
        ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"),
    ),
    (
        re.compile(r"^\s*(?P<stamp>\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2}(?: [AP]M)?)"),
        ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"),
    ),
]


def _decompress_blob(blob_path: str) -> str:
    """Decompress a zstd blob to a temporary file and return its path."""
    with open(blob_path, "rb") as fh:
        magic = fh.read(4)

    if magic != b"\x28\xb5\x2f\xfd":
        return blob_path

    dctx = zstandard.ZstdDecompressor()
    tmp = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
    try:
        with open(blob_path, "rb") as ifh, tmp:
            dctx.copy_stream(ifh, tmp)
    except Exception:
        os.unlink(tmp.name)
        raise
    return tmp.name


def _read_text(path: str) -> str:
    """Read text from a Defender log with forgiving encoding fallbacks."""
    with open(path, "rb") as fh:
        raw = fh.read()

    for encoding in ("utf-8-sig", "utf-16-le", "utf-16", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", errors="ignore")


def _parse_timestamp(line: str) -> str:
    """Extract a leading timestamp from a Defender log line."""
    for pattern, formats in _TIMESTAMP_PATTERNS:
        match = pattern.match(line)
        if not match:
            continue

        stamp = match.group("stamp")
        for fmt in formats:
            try:
                dt = datetime.strptime(stamp, fmt)
            except ValueError:
                continue

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_LOCAL_TZ)
            return dt.isoformat()

    return ""


def _infer_level(message: str) -> str:
    """Infer a rough severity from Defender log text."""
    lowered = message.lower()
    if any(token in lowered for token in ("error", "failed", "failure", "fatal")):
        return "Error"
    if any(token in lowered for token in ("warning", "warn", "threat", "malware", "quarantine", "blocked")):
        return "Warning"
    return "Information"


def _infer_source(source_path: str) -> str:
    """Map a Defender artifact path to a timeline source label."""
    lowered = source_path.lower()
    if "history" in lowered:
        return "defender_history"
    if "mplog-" in lowered or lowered.endswith(".log"):
        return "defender_mplog"
    return "defender"


def parse_defender_log(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
    source_path: str = "",
) -> int:
    """Parse a text-based Windows Defender log artifact."""
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path)
    cleanup_temp = decompressed != blob_path
    total = 0

    try:
        text = _read_text(decompressed)
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.commit()

        rows: list[tuple] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            message = line.strip()
            if not message:
                continue

            timestamp = _parse_timestamp(message)
            if not timestamp:
                continue

            rows.append((
                case_id,
                artifact_id,
                timestamp,
                _infer_source(source_path),
                0,
                _infer_level(message),
                "Defender",
                "Microsoft Defender",
                "",
                message,
                json.dumps({
                    "source_path": source_path,
                    "line_number": line_number,
                    "message": message,
                }),
            ))

            if len(rows) >= _BATCH_SIZE:
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
                total += len(rows)
                rows.clear()

        if rows:
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
            total += len(rows)

        conn.close()
    finally:
        if cleanup_temp:
            os.unlink(decompressed)

    log.info("Parsed %d Defender log events from artifact %s", total, artifact_id)
    return total
