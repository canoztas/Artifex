"""Timeline builder and query engine.

Builds a unified, chronological timeline from all events in a case and
provides cursor-based pagination for efficient retrieval.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

log = logging.getLogger("pickaxe.timeline")


def build_timeline(case_id: str, db_path: str) -> int:
    """Build (or rebuild) a merged chronological timeline for a case.

    This function ensures every event for the given case has a position in
    the ``timeline_index`` table, ordered by timestamp.  The index enables
    efficient cursor-based pagination without an expensive ``ORDER BY`` on
    every read.

    Parameters
    ----------
    case_id:
        The case to build the timeline for.
    db_path:
        Path to the Pickaxe SQLite database.

    Returns
    -------
    int
        Total number of events in the timeline.
    """
    conn = sqlite3.connect(db_path)

    # Ensure the timeline_index table exists.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS timeline_index (
            position    INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT    NOT NULL,
            event_id    TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            UNIQUE(case_id, event_id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_timeline_case_ts "
        "ON timeline_index (case_id, timestamp, position)"
    )
    conn.commit()

    # Clear existing index for this case (full rebuild).
    conn.execute(
        "DELETE FROM timeline_index WHERE case_id = ?",
        (case_id,),
    )
    conn.commit()

    # Insert events ordered by timestamp.  Events with identical timestamps
    # are sub-sorted by source and then rowid for deterministic ordering.
    conn.execute(
        """
        INSERT INTO timeline_index (case_id, event_id, timestamp)
        SELECT case_id, id, COALESCE(timestamp, '')
        FROM events
        WHERE case_id = ?
        ORDER BY timestamp ASC, source ASC, rowid ASC
        """,
        (case_id,),
    )
    conn.commit()

    count: int = conn.execute(
        "SELECT COUNT(*) FROM timeline_index WHERE case_id = ?",
        (case_id,),
    ).fetchone()[0]

    conn.close()

    log.info("Built timeline for case %s: %d events indexed", case_id, count)
    return count


def get_timeline(
    case_id: str,
    db_path: str,
    cursor: str | None = None,
    limit: int = 100,
    time_start: str | None = None,
    time_end: str | None = None,
) -> dict[str, Any]:
    """Retrieve a page of timeline events.

    Uses cursor-based pagination backed by the ``timeline_index`` table.

    Parameters
    ----------
    case_id:
        The case to query.
    db_path:
        Path to the Pickaxe SQLite database.
    cursor:
        Opaque cursor (position in ``timeline_index``) from a previous
        response.  ``None`` starts from the beginning.
    limit:
        Maximum number of events to return (clamped 1..1000).
    time_start:
        Optional ISO-8601 lower bound (inclusive) for filtering.
    time_end:
        Optional ISO-8601 upper bound (inclusive) for filtering.

    Returns
    -------
    dict
        ``{ "events": [...], "next_cursor": "...", "total": N }``
    """
    limit = max(1, min(limit, 1000))

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Build the query dynamically based on supplied filters.
    conditions: list[str] = ["ti.case_id = ?"]
    params: list[Any] = [case_id]

    if cursor is not None:
        try:
            cursor_pos = int(cursor)
        except ValueError:
            cursor_pos = 0
        conditions.append("ti.position > ?")
        params.append(cursor_pos)

    if time_start:
        conditions.append("ti.timestamp >= ?")
        params.append(time_start)

    if time_end:
        conditions.append("ti.timestamp <= ?")
        params.append(time_end)

    where = " AND ".join(conditions)
    count_params = list(params)
    params.append(limit)

    query = f"""
        SELECT
            ti.position,
            ti.timestamp  AS idx_timestamp,
            e.id,
            e.case_id,
            e.artifact_id,
            e.source,
            e.timestamp,
            e.event_id,
            e.level,
            e.channel,
            e.provider,
            e.computer,
            e.message,
            e.raw_data
        FROM timeline_index ti
        JOIN events e ON e.id = ti.event_id
        WHERE {where}
        ORDER BY ti.position ASC
        LIMIT ?
    """

    rows = conn.execute(query, params).fetchall()

    events: list[dict[str, Any]] = []
    last_position: int | None = None

    for row in rows:
        events.append({
            "id": row["id"],
            "case_id": row["case_id"],
            "artifact_id": row["artifact_id"],
            "source": row["source"],
            "timestamp": row["timestamp"],
            "event_id": row["event_id"],
            "level": row["level"],
            "channel": row["channel"],
            "provider": row["provider"],
            "computer": row["computer"],
            "message": row["message"],
            "raw_data": row["raw_data"],
        })
        last_position = row["position"]

    # Determine next cursor.
    next_cursor: str | None = None
    if last_position is not None and len(events) == limit:
        next_cursor = str(last_position)

    # Total count for this case (cached in the query; cheap because of the
    # index).
    total: int = conn.execute(
        f"SELECT COUNT(*) FROM timeline_index ti WHERE {where}",
        count_params,
    ).fetchone()[0]

    conn.close()

    return {
        "case_id": case_id,
        "events": events,
        "next_cursor": next_cursor,
        "total": total,
        "returned": len(events),
    }
