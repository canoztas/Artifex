"""YARA rule scanner.

Loads YARA rules from the Pickaxe database, decompresses evidence blobs,
and runs scans with strict size and time limits.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sqlite3
import tempfile
import threading
import time
from typing import Any

import yara
import zstandard

log = logging.getLogger("pickaxe.scanner.yara")

# Safety limits.
_MAX_BLOB_SIZE: int = 100 * 1024 * 1024  # 100 MB
_SCAN_TIMEOUT: int = 30                   # seconds per scan


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


def _load_rule(rule_id: str, db_path: str) -> dict[str, Any]:
    """Fetch a YARA rule definition from the database.

    Returns a dict with ``id``, ``name``, and ``source`` keys.
    Raises ``FileNotFoundError`` if the rule does not exist.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT id, name, source FROM yara_rules WHERE id = ?",
        (rule_id,),
    ).fetchone()
    conn.close()

    if row is None:
        raise FileNotFoundError(f"YARA rule not found: {rule_id}")

    return dict(row)


def _compile_rule(source: str) -> yara.Rules:
    """Compile a YARA rule from source text."""
    try:
        return yara.compile(source=source)
    except yara.SyntaxError as exc:
        raise ValueError(f"YARA syntax error: {exc}") from exc


def _scan_with_timeout(
    rules: yara.Rules,
    file_path: str,
    timeout: int = _SCAN_TIMEOUT,
) -> list[dict[str, Any]]:
    """Run a YARA scan with a timeout.

    Uses yara-python's built-in ``timeout`` parameter (in seconds).
    Returns a list of match dicts.
    """
    file_size = os.path.getsize(file_path)
    if file_size > _MAX_BLOB_SIZE:
        raise ValueError(
            f"Blob exceeds maximum size: {file_size} bytes > {_MAX_BLOB_SIZE} bytes"
        )

    try:
        matches = rules.match(file_path, timeout=timeout)
    except yara.TimeoutError:
        raise TimeoutError(
            f"YARA scan timed out after {timeout}s on {file_path}"
        )

    results: list[dict[str, Any]] = []
    for match in matches:
        match_info: dict[str, Any] = {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": dict(match.meta) if match.meta else {},
            "strings": [],
        }
        for string_match in match.strings:
            for instance in string_match.instances:
                match_info["strings"].append({
                    "identifier": string_match.identifier,
                    "offset": instance.offset,
                    "length": instance.matched_length,
                    # Only include the first 200 bytes of matched data to
                    # avoid storing huge blobs.
                    "data": instance.matched_data[:200].hex(),
                })
        results.append(match_info)

    return results


def _store_results(
    rule_id: str,
    artifact_id: str,
    case_id: str,
    matches: list[dict[str, Any]],
    db_path: str,
) -> None:
    """Persist scan results in the ``yara_results`` table."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT OR REPLACE INTO yara_results
            (rule_id, artifact_id, case_id, match_count, matches_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        """,
        (
            rule_id,
            artifact_id,
            case_id,
            len(matches),
            json.dumps(matches, default=str),
        ),
    )
    conn.commit()
    conn.close()


def scan_artifact(
    rule_id: str,
    artifact_id: str,
    case_id: str,
    db_path: str,
    evidence_path: str,
) -> dict[str, Any]:
    """Run a YARA rule against a specific evidence blob.

    Parameters
    ----------
    rule_id:
        ID of the YARA rule in the ``yara_rules`` table.
    artifact_id:
        ID of the artifact to scan.
    case_id:
        Parent case identifier.
    db_path:
        Path to the Pickaxe SQLite database.
    evidence_path:
        Base directory where evidence blobs are stored.

    Returns
    -------
    dict
        Summary with ``rule_id``, ``artifact_id``, ``total_matches``,
        and ``matches`` list.
    """
    rule_row = _load_rule(rule_id, db_path)
    rules = _compile_rule(rule_row["source"])

    blob_path = os.path.join(evidence_path, f"{artifact_id}.zst")
    if not os.path.isfile(blob_path):
        raise FileNotFoundError(f"Evidence blob not found: {blob_path}")

    decompressed = _decompress_blob(blob_path)
    cleanup = decompressed != blob_path

    try:
        matches = _scan_with_timeout(rules, decompressed, _SCAN_TIMEOUT)
    finally:
        if cleanup:
            os.unlink(decompressed)

    _store_results(rule_id, artifact_id, case_id, matches, db_path)

    log.info(
        "YARA scan: rule=%s artifact=%s matches=%d",
        rule_id, artifact_id, len(matches),
    )

    return {
        "rule_id": rule_id,
        "rule_name": rule_row["name"],
        "artifact_id": artifact_id,
        "total_matches": len(matches),
        "matches": matches,
    }


def scan_case(
    rule_id: str,
    case_id: str,
    db_path: str,
    evidence_path: str,
) -> dict[str, Any]:
    """Run a YARA rule against ALL artifacts in a case.

    Parameters
    ----------
    rule_id:
        ID of the YARA rule.
    case_id:
        Case to scan.
    db_path:
        Path to the Pickaxe SQLite database.
    evidence_path:
        Base directory where evidence blobs are stored.

    Returns
    -------
    dict
        Aggregated summary with per-artifact results.
    """
    rule_row = _load_rule(rule_id, db_path)
    rules = _compile_rule(rule_row["source"])

    # Fetch all artifact IDs for the case.
    conn = sqlite3.connect(db_path)
    artifact_rows = conn.execute(
        "SELECT id FROM artifacts WHERE case_id = ?",
        (case_id,),
    ).fetchall()
    conn.close()

    if not artifact_rows:
        log.info("No artifacts found for case %s", case_id)
        return {
            "rule_id": rule_id,
            "rule_name": rule_row["name"],
            "case_id": case_id,
            "artifacts_scanned": 0,
            "total_matches": 0,
            "results": [],
        }

    results: list[dict[str, Any]] = []
    total_matches = 0
    scanned = 0
    errors: list[dict[str, str]] = []

    for (artifact_id,) in artifact_rows:
        blob_path = os.path.join(evidence_path, f"{artifact_id}.zst")
        if not os.path.isfile(blob_path):
            log.warning("Blob missing for artifact %s; skipping", artifact_id)
            errors.append({"artifact_id": artifact_id, "error": "blob not found"})
            continue

        decompressed = _decompress_blob(blob_path)
        cleanup = decompressed != blob_path

        try:
            matches = _scan_with_timeout(rules, decompressed, _SCAN_TIMEOUT)
            _store_results(rule_id, artifact_id, case_id, matches, db_path)

            results.append({
                "artifact_id": artifact_id,
                "match_count": len(matches),
                "matches": matches,
            })
            total_matches += len(matches)
            scanned += 1
        except TimeoutError:
            log.warning("YARA scan timed out for artifact %s", artifact_id)
            errors.append({"artifact_id": artifact_id, "error": "timeout"})
        except ValueError as exc:
            log.warning("Skipping artifact %s: %s", artifact_id, exc)
            errors.append({"artifact_id": artifact_id, "error": str(exc)})
        except Exception as exc:
            log.exception("YARA scan error for artifact %s", artifact_id)
            errors.append({"artifact_id": artifact_id, "error": str(exc)})
        finally:
            if cleanup:
                os.unlink(decompressed)

    log.info(
        "YARA case scan: rule=%s case=%s scanned=%d matches=%d errors=%d",
        rule_id, case_id, scanned, total_matches, len(errors),
    )

    return {
        "rule_id": rule_id,
        "rule_name": rule_row["name"],
        "case_id": case_id,
        "artifacts_scanned": scanned,
        "total_matches": total_matches,
        "results": results,
        "errors": errors,
    }
