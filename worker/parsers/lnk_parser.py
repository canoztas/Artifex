"""Windows shortcut (.lnk) parser."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone

import zstandard

log = logging.getLogger("artifex.parser.lnk")

_LOCAL_TZ = datetime.now().astimezone().tzinfo or timezone.utc
_SCRIPT_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "scripts", "read_shortcut.ps1")
)


def _decompress_blob(blob_path: str) -> str:
    """Decompress a zstd blob to a temporary file and return its path."""
    with open(blob_path, "rb") as fh:
        magic = fh.read(4)

    if magic != b"\x28\xb5\x2f\xfd":
        return blob_path

    dctx = zstandard.ZstdDecompressor()
    tmp = tempfile.NamedTemporaryFile(suffix=".lnk", delete=False)
    try:
        with open(blob_path, "rb") as ifh, tmp:
            dctx.copy_stream(ifh, tmp)
    except Exception:
        os.unlink(tmp.name)
        raise
    return tmp.name


def _filetime_to_iso(timestamp: float | None) -> str:
    """Convert a filesystem timestamp into an ISO-8601 string."""
    if not timestamp:
        return ""
    return datetime.fromtimestamp(timestamp, tz=_LOCAL_TZ).isoformat()


def _stat_times(path: str) -> dict[str, str]:
    """Read file timestamps from the original shortcut when available."""
    if not path or not os.path.exists(path):
        return {}

    stat_result = os.stat(path)
    return {
        "created": _filetime_to_iso(getattr(stat_result, "st_ctime", None)),
        "modified": _filetime_to_iso(getattr(stat_result, "st_mtime", None)),
        "accessed": _filetime_to_iso(getattr(stat_result, "st_atime", None)),
    }


def _infer_source(source_path: str) -> str:
    """Map a shortcut path to a source label useful in timeline/search."""
    lowered = source_path.lower()
    if "\\recent\\" in lowered:
        return "lnk_recent"
    if "\\startup\\" in lowered:
        return "lnk_startup"
    if "\\desktop\\" in lowered:
        return "lnk_desktop"
    return "lnk"


def read_shortcut_metadata(shortcut_path: str) -> dict[str, object]:
    """Read a shortcut's metadata through the Windows Script Host COM API."""
    if os.name != "nt":
        raise RuntimeError("shortcut parsing requires Windows")

    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                _SCRIPT_PATH,
                "-ShortcutPath",
                shortcut_path,
            ],
            capture_output=True,
            text=True,
            check=True,
            creationflags=flags,
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        log.warning("Failed to extract shortcut metadata for %s: %s", shortcut_path, stderr or exc)
        return {}

    payload = result.stdout.strip()
    if not payload:
        return {}
    return json.loads(payload)


def parse_lnk(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
    source_path: str = "",
) -> int:
    """Parse a .lnk artifact and insert one normalized event."""
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path)
    cleanup_temp = decompressed != blob_path

    try:
        metadata = read_shortcut_metadata(decompressed)
        file_times = _stat_times(source_path) or _stat_times(decompressed)
        timestamp = file_times.get("modified", "")

        shortcut_name = os.path.basename(source_path or decompressed)
        target_path = str(metadata.get("target_path", "") or "")
        arguments = str(metadata.get("arguments", "") or "")

        message = f"Shortcut {shortcut_name}"
        if target_path:
            message += f" points to {target_path}"
        else:
            message += " has an unresolved target"
        if arguments:
            message += f" with arguments {arguments}"

        raw_data = json.dumps({
            "shortcut_name": shortcut_name,
            "source_path": source_path,
            "target_path": target_path,
            "arguments": arguments,
            "working_directory": metadata.get("working_directory", ""),
            "description": metadata.get("description", ""),
            "hotkey": metadata.get("hotkey", ""),
            "icon_location": metadata.get("icon_location", ""),
            "window_style": metadata.get("window_style", ""),
            "file_times": file_times,
        })

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.execute(
            """
            INSERT INTO events
                (case_id, artifact_id, timestamp, source, event_id, level,
                 channel, provider, computer, message, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                artifact_id,
                timestamp,
                _infer_source(source_path),
                0,
                "Information",
                "Shortcut",
                "Windows Shortcut",
                "",
                message,
                raw_data,
            ),
        )
        conn.commit()
        conn.close()
        return 1
    finally:
        if cleanup_temp:
            os.unlink(decompressed)
