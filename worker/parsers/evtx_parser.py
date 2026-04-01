"""EVTX (Windows Event Log) parser.

Decompresses a zstd-compressed EVTX blob, walks every record with
python-evtx, extracts normalised fields, and batch-inserts them into the
Artifex ``events`` table.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import tempfile
from typing import Any
from xml.etree import ElementTree

import zstandard
import Evtx.Evtx as evtx

log = logging.getLogger("artifex.parser.evtx")

# XML namespace used inside EVTX records.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Maximum batch size for DB inserts.
_BATCH_SIZE = 500


def _decompress_blob(blob_path: str) -> str:
    """Decompress a zstd blob to a temporary file and return its path.

    If the file does not look zstd-compressed (no magic bytes), the
    original path is returned unchanged so callers can work with raw files.
    """
    with open(blob_path, "rb") as fh:
        magic = fh.read(4)

    # zstd magic number: 0xFD2FB528 (little-endian).
    if magic != b"\x28\xb5\x2f\xfd":
        log.debug("Blob %s is not zstd-compressed; using raw file", blob_path)
        return blob_path

    dctx = zstandard.ZstdDecompressor()
    tmp = tempfile.NamedTemporaryFile(suffix=".evtx", delete=False)
    try:
        with open(blob_path, "rb") as ifh, tmp:
            dctx.copy_stream(ifh, tmp)
    except Exception:
        os.unlink(tmp.name)
        raise
    return tmp.name


def _text(element: ElementTree.Element | None) -> str:
    """Safely extract text from an XML element."""
    if element is None:
        return ""
    return (element.text or "").strip()


def _extract_event(record_xml: str) -> dict[str, Any] | None:
    """Parse a single EVTX XML record into a flat dict.

    Returns ``None`` when the record is malformed or unparseable.
    """
    try:
        root = ElementTree.fromstring(record_xml)
    except ElementTree.ParseError:
        return None

    system = root.find(f"{_NS}System")
    if system is None:
        return None

    time_created_el = system.find(f"{_NS}TimeCreated")
    timestamp = time_created_el.get("SystemTime", "") if time_created_el is not None else ""

    event_id_el = system.find(f"{_NS}EventID")
    event_id = _text(event_id_el)
    # Some EventID elements carry a Qualifiers attribute; prefer text.
    if event_id_el is not None and not event_id:
        event_id = event_id_el.get("Qualifiers", "")

    level = _text(system.find(f"{_NS}Level"))
    channel = _text(system.find(f"{_NS}Channel"))
    computer = _text(system.find(f"{_NS}Computer"))

    provider_el = system.find(f"{_NS}Provider")
    provider = provider_el.get("Name", "") if provider_el is not None else ""

    level_map = {
        "1": "Critical",
        "2": "Error",
        "3": "Warning",
        "4": "Information",
        "5": "Verbose",
    }

    # Build a flat message from EventData / UserData if available.
    message_parts: list[str] = []
    for section_tag in ("EventData", "UserData"):
        section = root.find(f"{_NS}{section_tag}")
        if section is None:
            continue
        for child in section:
            name = child.get("Name", child.tag.split("}")[-1] if "}" in child.tag else child.tag)
            value = _text(child)
            if value:
                message_parts.append(f"{name}={value}")
    message = "; ".join(message_parts)

    return {
        "timestamp": timestamp,
        "event_id": int(event_id) if str(event_id).isdigit() else 0,
        "level": level_map.get(level, "Information"),
        "channel": channel,
        "provider": provider,
        "computer": computer,
        "message": message,
        "raw_xml": record_xml,
    }


def _insert_batch(
    conn: sqlite3.Connection,
    rows: list[tuple],
) -> None:
    """Batch-insert rows into the events table."""
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


def parse_evtx(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
) -> int:
    """Parse an EVTX blob, extract events, and insert into the events table.

    Parameters
    ----------
    artifact_id:
        Unique identifier of the artifact in the Artifex database.
    case_id:
        Case the artifact belongs to.
    blob_path:
        Path to the (possibly zstd-compressed) EVTX file on disk.
    db_path:
        Path to the Artifex SQLite database.

    Returns
    -------
    int
        Number of events successfully parsed and stored.
    """
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path)
    cleanup_temp = decompressed != blob_path
    total = 0

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))
        conn.commit()
        batch: list[tuple] = []

        with evtx.Evtx(decompressed) as ef:
            for record in ef.records():
                try:
                    xml_str: str = record.xml()
                except Exception:
                    log.warning(
                        "Malformed EVTX record in artifact %s (record %s); skipping",
                        artifact_id,
                        getattr(record, "record_num", "?"),
                    )
                    continue

                parsed = _extract_event(xml_str)
                if parsed is None:
                    continue

                batch.append((
                    case_id,
                    artifact_id,
                    parsed["timestamp"],
                    parsed["channel"] or parsed["provider"] or "evtx",
                    parsed["event_id"],
                    parsed["level"],
                    parsed["channel"],
                    parsed["provider"],
                    parsed["computer"],
                    parsed["message"],
                    parsed["raw_xml"],
                ))

                if len(batch) >= _BATCH_SIZE:
                    _insert_batch(conn, batch)
                    total += len(batch)
                    batch.clear()

        # Flush remaining rows.
        if batch:
            _insert_batch(conn, batch)
            total += len(batch)

        conn.close()
    finally:
        if cleanup_temp:
            os.unlink(decompressed)

    log.info("Parsed %d EVTX events from artifact %s", total, artifact_id)
    return total
