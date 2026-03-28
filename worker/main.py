"""Pickaxe Worker Service -- DFIR artifact parsing, YARA scanning, and timeline building.

Exposes an HTTP API on port 8083 (bound to 127.0.0.1) that the main API
server calls to offload CPU-intensive forensic work.
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import json
import hashlib
import logging
from typing import Any

from parsers.evtx_parser import parse_evtx
from parsers.prefetch_parser import parse_prefetch
from parsers.amcache_parser import parse_amcache
from parsers.shimcache_parser import parse_shimcache
from parsers.registry_parser import parse_registry_hive, extract_persistence_keys
from scanner.yara_scanner import scan_artifact, scan_case
from timeline.builder import build_timeline, get_timeline

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

WORKER_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(WORKER_DIR)

DB_PATH: str = os.environ.get("PICKAXE_DB", os.path.join(BASE_DIR, "data", "pickaxe.db"))
EVIDENCE_PATH: str = os.environ.get("PICKAXE_EVIDENCE", os.path.join(BASE_DIR, "evidence"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("pickaxe.worker")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_json_fields(data: dict | None, *fields: str) -> tuple[bool, str]:
    """Validate that all *fields* are present in *data*.

    Returns (ok, error_message).
    """
    if data is None:
        return False, "Request body must be JSON"
    missing = [f for f in fields if f not in data]
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    return True, ""


def _blob_path(artifact_id: str) -> str:
    """Resolve the on-disk path for a stored evidence blob."""
    return os.path.join(EVIDENCE_PATH, f"{artifact_id}.zst")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.route("/health", methods=["GET"])
def health() -> tuple:
    """Simple health-check endpoint."""
    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------------------------------
# Parser endpoints
# ---------------------------------------------------------------------------


@app.route("/parse/evtx", methods=["POST"])
def route_parse_evtx() -> tuple:
    """Parse an EVTX artifact and store normalised events in the DB."""
    data = request.get_json(silent=True)
    ok, err = _require_json_fields(data, "artifact_id", "case_id")
    if not ok:
        return jsonify({"error": err}), 400

    artifact_id: str = data["artifact_id"]
    case_id: str = data["case_id"]
    blob = data.get("blob_path", _blob_path(artifact_id))

    try:
        count = parse_evtx(artifact_id, case_id, blob, DB_PATH)
        log.info("Parsed %d EVTX events for artifact %s", count, artifact_id)
        return jsonify({"artifact_id": artifact_id, "events_parsed": count}), 200
    except FileNotFoundError:
        return jsonify({"error": f"Blob not found: {blob}"}), 404
    except Exception as exc:
        log.exception("EVTX parse failed for artifact %s", artifact_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/parse/prefetch", methods=["POST"])
def route_parse_prefetch() -> tuple:
    """Parse a Windows Prefetch file."""
    data = request.get_json(silent=True)
    ok, err = _require_json_fields(data, "artifact_id", "case_id")
    if not ok:
        return jsonify({"error": err}), 400

    artifact_id: str = data["artifact_id"]
    case_id: str = data["case_id"]
    blob = data.get("blob_path", _blob_path(artifact_id))

    try:
        count = parse_prefetch(artifact_id, case_id, blob, DB_PATH)
        log.info("Parsed %d prefetch events for artifact %s", count, artifact_id)
        return jsonify({"artifact_id": artifact_id, "events_parsed": count}), 200
    except FileNotFoundError:
        return jsonify({"error": f"Blob not found: {blob}"}), 404
    except Exception as exc:
        log.exception("Prefetch parse failed for artifact %s", artifact_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/parse/amcache", methods=["POST"])
def route_parse_amcache() -> tuple:
    """Parse an AmCache hive for execution artifacts."""
    data = request.get_json(silent=True)
    ok, err = _require_json_fields(data, "artifact_id", "case_id")
    if not ok:
        return jsonify({"error": err}), 400

    artifact_id: str = data["artifact_id"]
    case_id: str = data["case_id"]
    blob = data.get("blob_path", _blob_path(artifact_id))

    try:
        count = parse_amcache(artifact_id, case_id, blob, DB_PATH)
        log.info("Parsed %d amcache events for artifact %s", count, artifact_id)
        return jsonify({"artifact_id": artifact_id, "events_parsed": count}), 200
    except FileNotFoundError:
        return jsonify({"error": f"Blob not found: {blob}"}), 404
    except Exception as exc:
        log.exception("AmCache parse failed for artifact %s", artifact_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/parse/shimcache", methods=["POST"])
def route_parse_shimcache() -> tuple:
    """Parse ShimCache (AppCompatCache) data."""
    data = request.get_json(silent=True)
    ok, err = _require_json_fields(data, "artifact_id", "case_id")
    if not ok:
        return jsonify({"error": err}), 400

    artifact_id: str = data["artifact_id"]
    case_id: str = data["case_id"]
    blob = data.get("blob_path", _blob_path(artifact_id))

    try:
        count = parse_shimcache(artifact_id, case_id, blob, DB_PATH)
        log.info("Parsed %d shimcache events for artifact %s", count, artifact_id)
        return jsonify({"artifact_id": artifact_id, "events_parsed": count}), 200
    except FileNotFoundError:
        return jsonify({"error": f"Blob not found: {blob}"}), 404
    except Exception as exc:
        log.exception("ShimCache parse failed for artifact %s", artifact_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/parse/registry", methods=["POST"])
def route_parse_registry() -> tuple:
    """Parse a registry hive file."""
    data = request.get_json(silent=True)
    ok, err = _require_json_fields(data, "artifact_id", "case_id")
    if not ok:
        return jsonify({"error": err}), 400

    artifact_id: str = data["artifact_id"]
    case_id: str = data["case_id"]
    blob = data.get("blob_path", _blob_path(artifact_id))
    persistence_only: bool = data.get("persistence_only", False)

    try:
        if persistence_only:
            count = extract_persistence_keys(artifact_id, case_id, blob, DB_PATH)
        else:
            count = parse_registry_hive(artifact_id, case_id, blob, DB_PATH)
        log.info("Parsed %d registry events for artifact %s", count, artifact_id)
        return jsonify({"artifact_id": artifact_id, "events_parsed": count}), 200
    except FileNotFoundError:
        return jsonify({"error": f"Blob not found: {blob}"}), 404
    except Exception as exc:
        log.exception("Registry parse failed for artifact %s", artifact_id)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# YARA endpoints
# ---------------------------------------------------------------------------


@app.route("/yara/scan", methods=["POST"])
def route_yara_scan() -> tuple:
    """Run a YARA rule against one or all artifacts in a case."""
    data = request.get_json(silent=True)
    ok, err = _require_json_fields(data, "rule_id", "case_id")
    if not ok:
        return jsonify({"error": err}), 400

    rule_id: str = data["rule_id"]
    case_id: str = data["case_id"]
    artifact_id: str | None = data.get("artifact_id")

    try:
        if artifact_id:
            results = scan_artifact(rule_id, artifact_id, case_id, DB_PATH, EVIDENCE_PATH)
        else:
            results = scan_case(rule_id, case_id, DB_PATH, EVIDENCE_PATH)
        log.info(
            "YARA scan completed: rule=%s case=%s matches=%d",
            rule_id, case_id, results.get("total_matches", 0),
        )
        return jsonify(results), 200
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    except TimeoutError:
        return jsonify({"error": "YARA scan timed out (30 s limit)"}), 504
    except Exception as exc:
        log.exception("YARA scan failed: rule=%s case=%s", rule_id, case_id)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Timeline endpoints
# ---------------------------------------------------------------------------


@app.route("/timeline/build", methods=["POST"])
def route_timeline_build() -> tuple:
    """Build a merged chronological timeline for a case."""
    data = request.get_json(silent=True)
    ok, err = _require_json_fields(data, "case_id")
    if not ok:
        return jsonify({"error": err}), 400

    case_id: str = data["case_id"]

    try:
        count = build_timeline(case_id, DB_PATH)
        log.info("Built timeline for case %s: %d events", case_id, count)
        return jsonify({"case_id": case_id, "event_count": count}), 200
    except Exception as exc:
        log.exception("Timeline build failed for case %s", case_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/timeline/<case_id>", methods=["GET"])
def route_timeline_get(case_id: str) -> tuple:
    """Get a paginated timeline for a case."""
    cursor = request.args.get("cursor")
    limit = request.args.get("limit", 100, type=int)
    time_start = request.args.get("time_start")
    time_end = request.args.get("time_end")

    # Clamp limit to a sane range.
    limit = max(1, min(limit, 1000))

    try:
        result = get_timeline(
            case_id, DB_PATH,
            cursor=cursor,
            limit=limit,
            time_start=time_start,
            time_end=time_end,
        )
        return jsonify(result), 200
    except Exception as exc:
        log.exception("Timeline fetch failed for case %s", case_id)
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from waitress import serve

    port = int(os.environ.get("PICKAXE_WORKER_PORT", "8083"))
    log.info("Pickaxe worker starting on 127.0.0.1:%d", port)
    serve(app, host="127.0.0.1", port=port)
