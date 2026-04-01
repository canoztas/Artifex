"""Windows Jump List parser.

Parses both automatic and custom destination Jump List containers and
extracts embedded shortcut entries into the Artifex events table.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import struct
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone

import zstandard

from parsers.lnk_parser import read_shortcut_metadata

log = logging.getLogger("artifex.parser.jumplist")

_LOCAL_TZ = datetime.now().astimezone().tzinfo or timezone.utc
_CFBF_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
_FREE_SECT = 0xFFFFFFFF
_END_OF_CHAIN = 0xFFFFFFFE
_LNK_HEADER = bytes.fromhex("4C0000000114020000000000C000000000000046")


@dataclass
class _DirectoryEntry:
    name: str
    object_type: int
    start_sector: int
    size: int


class _CompoundFileReader:
    """Minimal CFBF reader for automatic Jump Lists."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or data[:8] != _CFBF_SIGNATURE:
            raise ValueError("not a compound file")

        self._data = data
        self.sector_size = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self.mini_sector_size = 1 << struct.unpack_from("<H", data, 0x20)[0]
        self.first_dir_sector = struct.unpack_from("<I", data, 0x30)[0]
        self.mini_stream_cutoff = struct.unpack_from("<I", data, 0x38)[0]
        self.first_mini_fat_sector = struct.unpack_from("<I", data, 0x3C)[0]
        self.num_mini_fat_sectors = struct.unpack_from("<I", data, 0x40)[0]
        self.first_difat_sector = struct.unpack_from("<I", data, 0x44)[0]
        self.num_difat_sectors = struct.unpack_from("<I", data, 0x48)[0]

        self.fat = self._load_fat()
        self.directory_entries = self._load_directory_entries()
        self.root_entry = next((entry for entry in self.directory_entries if entry.object_type == 5), None)
        self.mini_fat = self._load_mini_fat()
        self.mini_stream = self._load_mini_stream()

    def _sector_offset(self, sector_id: int) -> int:
        return (sector_id + 1) * self.sector_size

    def _read_sector(self, sector_id: int) -> bytes:
        offset = self._sector_offset(sector_id)
        return self._data[offset:offset + self.sector_size]

    def _load_fat(self) -> list[int]:
        difat = list(struct.unpack_from("<109I", self._data, 0x4C))
        next_sector = self.first_difat_sector
        entries_per_sector = (self.sector_size // 4) - 1

        for _ in range(self.num_difat_sectors):
            if next_sector in (_FREE_SECT, _END_OF_CHAIN):
                break
            sector = self._read_sector(next_sector)
            values = struct.unpack(f"<{entries_per_sector + 1}I", sector[: self.sector_size])
            difat.extend(values[:entries_per_sector])
            next_sector = values[-1]

        fat: list[int] = []
        entries_per_sector = self.sector_size // 4
        for sector_id in difat:
            if sector_id in (_FREE_SECT, _END_OF_CHAIN):
                continue
            sector = self._read_sector(sector_id)
            fat.extend(struct.unpack(f"<{entries_per_sector}I", sector))
        return fat

    def _read_chain(self, start_sector: int) -> bytes:
        if start_sector in (_FREE_SECT, _END_OF_CHAIN):
            return b""

        chunks: list[bytes] = []
        current = start_sector
        seen: set[int] = set()

        while current not in (_FREE_SECT, _END_OF_CHAIN):
            if current in seen or current >= len(self.fat):
                break
            seen.add(current)
            chunks.append(self._read_sector(current))
            current = self.fat[current]

        return b"".join(chunks)

    def _load_directory_entries(self) -> list[_DirectoryEntry]:
        directory_stream = self._read_chain(self.first_dir_sector)
        entries: list[_DirectoryEntry] = []

        for offset in range(0, len(directory_stream), 128):
            chunk = directory_stream[offset:offset + 128]
            if len(chunk) < 128:
                break

            name_len = struct.unpack_from("<H", chunk, 0x40)[0]
            raw_name = chunk[: max(0, name_len - 2)]
            try:
                name = raw_name.decode("utf-16-le")
            except UnicodeDecodeError:
                name = ""

            entries.append(_DirectoryEntry(
                name=name,
                object_type=chunk[0x42],
                start_sector=struct.unpack_from("<I", chunk, 0x74)[0],
                size=struct.unpack_from("<Q", chunk, 0x78)[0],
            ))

        return entries

    def _load_mini_fat(self) -> list[int]:
        if self.first_mini_fat_sector in (_FREE_SECT, _END_OF_CHAIN) or self.num_mini_fat_sectors == 0:
            return []

        data = self._read_chain(self.first_mini_fat_sector)
        entries_per_sector = self.sector_size // 4
        total_entries = self.num_mini_fat_sectors * entries_per_sector
        return list(struct.unpack(f"<{total_entries}I", data[: total_entries * 4]))

    def _load_mini_stream(self) -> bytes:
        if not self.root_entry or self.root_entry.start_sector in (_FREE_SECT, _END_OF_CHAIN):
            return b""
        return self._read_chain(self.root_entry.start_sector)[: self.root_entry.size]

    def _read_mini_stream(self, start_sector: int, size: int) -> bytes:
        if start_sector in (_FREE_SECT, _END_OF_CHAIN) or not self.mini_fat or not self.mini_stream:
            return b""

        chunks: list[bytes] = []
        current = start_sector
        seen: set[int] = set()

        while current not in (_FREE_SECT, _END_OF_CHAIN):
            if current in seen or current >= len(self.mini_fat):
                break
            seen.add(current)
            offset = current * self.mini_sector_size
            chunks.append(self.mini_stream[offset:offset + self.mini_sector_size])
            current = self.mini_fat[current]

        return b"".join(chunks)[:size]

    def read_stream(self, entry: _DirectoryEntry) -> bytes:
        if entry.size < self.mini_stream_cutoff:
            return self._read_mini_stream(entry.start_sector, entry.size)
        return self._read_chain(entry.start_sector)[:entry.size]


def _decompress_blob(blob_path: str, suffix: str) -> str:
    with open(blob_path, "rb") as fh:
        magic = fh.read(4)

    if magic != b"\x28\xb5\x2f\xfd":
        return blob_path

    dctx = zstandard.ZstdDecompressor()
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    try:
        with open(blob_path, "rb") as ifh, tmp:
            dctx.copy_stream(ifh, tmp)
    except Exception:
        os.unlink(tmp.name)
        raise
    return tmp.name


def _filetime_to_iso(timestamp: float | None) -> str:
    if not timestamp:
        return ""
    return datetime.fromtimestamp(timestamp, tz=_LOCAL_TZ).isoformat()


def _stat_times(path: str) -> dict[str, str]:
    if not path or not os.path.exists(path):
        return {}

    stat_result = os.stat(path)
    return {
        "created": _filetime_to_iso(getattr(stat_result, "st_ctime", None)),
        "modified": _filetime_to_iso(getattr(stat_result, "st_mtime", None)),
        "accessed": _filetime_to_iso(getattr(stat_result, "st_atime", None)),
    }


def _pick_timestamp(file_times: dict[str, str]) -> str:
    return file_times.get("modified", "") or file_times.get("accessed", "") or file_times.get("created", "")


def _infer_source(source_path: str) -> str:
    lowered = source_path.lower()
    if lowered.endswith(".automaticdestinations-ms"):
        return "jumplist_automatic"
    if lowered.endswith(".customdestinations-ms"):
        return "jumplist_custom"
    return "jumplist"


def _extract_app_id(source_path: str) -> str:
    base = os.path.basename(source_path)
    if "." in base:
        return base.split(".", 1)[0]
    return base


def _extract_lnk_streams_from_automatic(path: str) -> list[tuple[str, bytes]]:
    with open(path, "rb") as fh:
        data = fh.read()

    reader = _CompoundFileReader(data)
    streams: list[tuple[str, bytes]] = []

    for entry in reader.directory_entries:
        if entry.object_type != 2 or not entry.name or entry.name == "DestList":
            continue
        payload = reader.read_stream(entry)
        if payload.startswith(_LNK_HEADER):
            streams.append((entry.name, payload))

    return streams


def _extract_lnk_streams_from_custom(path: str) -> list[tuple[str, bytes]]:
    with open(path, "rb") as fh:
        data = fh.read()

    streams: list[tuple[str, bytes]] = []
    offsets: list[int] = []
    start = 0
    while True:
        idx = data.find(_LNK_HEADER, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1

    for index, offset in enumerate(offsets):
        end = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        streams.append((str(index + 1), data[offset:end]))

    return streams


def _extract_entries(path: str, source_path: str) -> list[tuple[str, bytes]]:
    if source_path.lower().endswith(".automaticdestinations-ms"):
        return _extract_lnk_streams_from_automatic(path)
    return _extract_lnk_streams_from_custom(path)


def parse_jumplist(
    artifact_id: str,
    case_id: str,
    blob_path: str,
    db_path: str,
    source_path: str = "",
) -> int:
    """Parse a Jump List container and insert normalized entry events."""
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path, ".jumplist")
    cleanup_temp = decompressed != blob_path
    total = 0

    try:
        file_times = _stat_times(source_path) or _stat_times(decompressed)
        timestamp = _pick_timestamp(file_times)
        app_id = _extract_app_id(source_path or decompressed)
        source_label = _infer_source(source_path or decompressed)
        entries = _extract_entries(decompressed, source_path or decompressed)

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE artifact_id = ?", (artifact_id,))

        rows: list[tuple] = []
        for entry_index, (entry_name, payload) in enumerate(entries, start=1):
            temp_link = tempfile.NamedTemporaryFile(suffix=".lnk", delete=False)
            try:
                with temp_link:
                    temp_link.write(payload)
                metadata = read_shortcut_metadata(temp_link.name)
            finally:
                os.unlink(temp_link.name)

            target_path = str(metadata.get("target_path", "") or "")
            arguments = str(metadata.get("arguments", "") or "")
            message = f"Jump List entry from {app_id}"
            if target_path:
                message += f" references {target_path}"
            else:
                message += " references an unresolved shortcut target"
            if arguments:
                message += f" with arguments {arguments}"

            rows.append((
                case_id,
                artifact_id,
                timestamp,
                source_label,
                0,
                "Information",
                "Jump List",
                "Windows Jump List",
                "",
                message,
                json.dumps({
                    "app_id": app_id,
                    "entry_index": entry_index,
                    "entry_name": entry_name,
                    "source_path": source_path,
                    "target_path": target_path,
                    "arguments": arguments,
                    "working_directory": metadata.get("working_directory", ""),
                    "description": metadata.get("description", ""),
                    "icon_location": metadata.get("icon_location", ""),
                    "window_style": metadata.get("window_style", ""),
                    "file_times": file_times,
                    "timestamp_basis": "jumplist_container_time",
                }),
            ))

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
            total = len(rows)

        conn.close()
        return total
    finally:
        if cleanup_temp:
            os.unlink(decompressed)
