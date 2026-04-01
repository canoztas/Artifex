package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/artifex/dfir/internal/models"

	_ "modernc.org/sqlite"
)

// DB wraps a sql.DB connection to the SQLite database.
type DB struct {
	conn *sql.DB
}

// Init opens (or creates) the SQLite database at dbPath, enables WAL mode,
// creates all tables if they do not exist, and returns a ready DB handle.
func Init(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode for better concurrent read performance.
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}

	// Enable foreign keys.
	if _, err := conn.Exec("PRAGMA foreign_keys=ON"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.createTables(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	return db, nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn returns the underlying *sql.DB connection.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) createTables() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cases (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL,
			updated_at  TEXT NOT NULL,
			status      TEXT NOT NULL DEFAULT 'active'
		)`,

		`CREATE TABLE IF NOT EXISTS artifacts (
			id                TEXT PRIMARY KEY,
			case_id           TEXT NOT NULL REFERENCES cases(id),
			type              TEXT NOT NULL,
			source            TEXT NOT NULL,
			collection_method TEXT NOT NULL DEFAULT '',
			collector_version TEXT NOT NULL DEFAULT '',
			privileges_used   TEXT NOT NULL DEFAULT '',
			sha256            TEXT NOT NULL,
			compression       TEXT NOT NULL DEFAULT 'zstd',
			size_raw          INTEGER NOT NULL DEFAULT 0,
			size_compressed   INTEGER NOT NULL DEFAULT 0,
			collected_at      TEXT NOT NULL,
			blob_path         TEXT NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS artifact_source_cache (
			case_id         TEXT NOT NULL REFERENCES cases(id),
			artifact_type   TEXT NOT NULL,
			source          TEXT NOT NULL,
			source_size     INTEGER NOT NULL DEFAULT 0,
			source_mod_time TEXT NOT NULL DEFAULT '',
			artifact_id     TEXT NOT NULL REFERENCES artifacts(id),
			sha256          TEXT NOT NULL DEFAULT '',
			updated_at      TEXT NOT NULL,
			PRIMARY KEY (case_id, artifact_type, source)
		)`,

		`CREATE TABLE IF NOT EXISTS events (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			case_id     TEXT NOT NULL REFERENCES cases(id),
			artifact_id TEXT NOT NULL REFERENCES artifacts(id),
			timestamp   TEXT NOT NULL,
			source      TEXT NOT NULL DEFAULT '',
			event_id    INTEGER NOT NULL DEFAULT 0,
			level       TEXT NOT NULL DEFAULT '',
			channel     TEXT NOT NULL DEFAULT '',
			provider    TEXT NOT NULL DEFAULT '',
			computer    TEXT NOT NULL DEFAULT '',
			message     TEXT NOT NULL DEFAULT '',
			raw_data    TEXT NOT NULL DEFAULT ''
		)`,

		`CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
			message,
			raw_data,
			content=events,
			content_rowid=id
		)`,

		// Triggers to keep FTS index in sync with the events table.
		`CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
			INSERT INTO events_fts(rowid, message, raw_data) VALUES (new.id, new.message, new.raw_data);
		END`,

		`CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
			INSERT INTO events_fts(events_fts, rowid, message, raw_data) VALUES ('delete', old.id, old.message, old.raw_data);
		END`,

		`CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
			INSERT INTO events_fts(events_fts, rowid, message, raw_data) VALUES ('delete', old.id, old.message, old.raw_data);
			INSERT INTO events_fts(rowid, message, raw_data) VALUES (new.id, new.message, new.raw_data);
		END`,

		`CREATE TABLE IF NOT EXISTS collection_jobs (
			id                  TEXT PRIMARY KEY,
			case_id             TEXT NOT NULL REFERENCES cases(id),
			preset              TEXT NOT NULL DEFAULT 'standard',
			status              TEXT NOT NULL DEFAULT 'pending',
			progress            REAL NOT NULL DEFAULT 0,
			started_at          TEXT,
			completed_at        TEXT,
			error               TEXT NOT NULL DEFAULT '',
			artifacts_collected INTEGER NOT NULL DEFAULT 0,
			steps               TEXT NOT NULL DEFAULT '[]'
		)`,

		`CREATE TABLE IF NOT EXISTS yara_rules (
			id         TEXT PRIMARY KEY,
			case_id    TEXT NOT NULL REFERENCES cases(id),
			name       TEXT NOT NULL,
			content    TEXT NOT NULL,
			created_at TEXT NOT NULL,
			created_by TEXT NOT NULL DEFAULT 'user'
		)`,

		`CREATE TABLE IF NOT EXISTS yara_results (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			case_id     TEXT NOT NULL REFERENCES cases(id),
			rule_id     TEXT NOT NULL REFERENCES yara_rules(id),
			artifact_id TEXT NOT NULL REFERENCES artifacts(id),
			matches     TEXT NOT NULL DEFAULT '[]',
			scanned_at  TEXT NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS action_proposals (
			id          TEXT PRIMARY KEY,
			case_id     TEXT NOT NULL REFERENCES cases(id),
			type        TEXT NOT NULL,
			title       TEXT NOT NULL,
			rationale   TEXT NOT NULL DEFAULT '',
			steps       TEXT NOT NULL DEFAULT '[]',
			status      TEXT NOT NULL DEFAULT 'pending',
			created_at  TEXT NOT NULL,
			approved_at TEXT,
			executed_at TEXT,
			result      TEXT NOT NULL DEFAULT ''
		)`,

		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			case_id    TEXT NOT NULL REFERENCES cases(id),
			timestamp  TEXT NOT NULL,
			actor      TEXT NOT NULL,
			action     TEXT NOT NULL,
			tool       TEXT NOT NULL DEFAULT '',
			details    TEXT NOT NULL DEFAULT '',
			prev_hash  TEXT NOT NULL DEFAULT '',
			entry_hash TEXT NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS persistence_items (
			id       TEXT PRIMARY KEY,
			case_id  TEXT NOT NULL REFERENCES cases(id),
			type     TEXT NOT NULL,
			location TEXT NOT NULL,
			value    TEXT NOT NULL DEFAULT '',
			details  TEXT NOT NULL DEFAULT ''
		)`,

		`CREATE INDEX IF NOT EXISTS idx_artifacts_case_collected_at
		 ON artifacts(case_id, collected_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_artifacts_case_type_source_sha256
		 ON artifacts(case_id, type, source, sha256)`,
		`CREATE INDEX IF NOT EXISTS idx_events_artifact_id
		 ON events(artifact_id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_case_timestamp
		 ON events(case_id, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_case_source_timestamp
		 ON events(case_id, source, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_case_level_timestamp
		 ON events(case_id, level, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_case_event_id
		 ON events(case_id, event_id)`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_case_started
		 ON collection_jobs(case_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_source_cache_lookup
		 ON artifact_source_cache(case_id, artifact_type, source, source_mod_time, source_size)`,
	}

	for _, stmt := range statements {
		if _, err := db.conn.Exec(stmt); err != nil {
			return fmt.Errorf("exec %q: %w", stmt[:60], err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

// CreateCase inserts a new case record.
func (db *DB) CreateCase(c models.Case) error {
	_, err := db.conn.Exec(
		`INSERT INTO cases (id, name, description, created_at, updated_at, status)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Description,
		c.CreatedAt.Format(time.RFC3339Nano),
		c.UpdatedAt.Format(time.RFC3339Nano),
		c.Status,
	)
	if err != nil {
		return fmt.Errorf("create case: %w", err)
	}
	return nil
}

// GetCase retrieves a single case by ID.
func (db *DB) GetCase(id string) (*models.Case, error) {
	row := db.conn.QueryRow(
		`SELECT id, name, description, created_at, updated_at, status FROM cases WHERE id = ?`, id,
	)
	return scanCase(row)
}

// ListCases returns all cases ordered by creation time descending.
func (db *DB) ListCases() ([]models.Case, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, description, created_at, updated_at, status FROM cases ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list cases: %w", err)
	}
	defer rows.Close()

	var cases []models.Case
	for rows.Next() {
		c, err := scanCaseRows(rows)
		if err != nil {
			return nil, err
		}
		cases = append(cases, *c)
	}
	return cases, rows.Err()
}

// UpdateCaseStatus updates the status and updated_at timestamp of a case.
func (db *DB) UpdateCaseStatus(id, status string) error {
	res, err := db.conn.Exec(
		`UPDATE cases SET status = ?, updated_at = ? WHERE id = ?`,
		status, time.Now().UTC().Format(time.RFC3339Nano), id,
	)
	if err != nil {
		return fmt.Errorf("update case status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteCase removes a case by ID.
func (db *DB) DeleteCase(id string) error {
	res, err := db.conn.Exec(`DELETE FROM cases WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete case: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanCase(row *sql.Row) (*models.Case, error) {
	var c models.Case
	var createdAt, updatedAt string
	if err := row.Scan(&c.ID, &c.Name, &c.Description, &createdAt, &updatedAt, &c.Status); err != nil {
		return nil, fmt.Errorf("scan case: %w", err)
	}
	var err error
	c.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	c.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &c, nil
}

func scanCaseRows(rows *sql.Rows) (*models.Case, error) {
	var c models.Case
	var createdAt, updatedAt string
	if err := rows.Scan(&c.ID, &c.Name, &c.Description, &createdAt, &updatedAt, &c.Status); err != nil {
		return nil, fmt.Errorf("scan case row: %w", err)
	}
	var err error
	c.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	c.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &c, nil
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

// CreateArtifact inserts a new artifact record.
func (db *DB) CreateArtifact(a *models.Artifact) error {
	_, err := db.conn.Exec(
		`INSERT INTO artifacts (id, case_id, type, source, collection_method, collector_version,
		 privileges_used, sha256, compression, size_raw, size_compressed, collected_at, blob_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.CaseID, a.Type, a.Source, a.CollectionMethod, a.CollectorVersion,
		a.PrivilegesUsed, a.SHA256, a.Compression, a.SizeRaw, a.SizeCompressed,
		a.CollectedAt.Format(time.RFC3339Nano), a.BlobPath,
	)
	if err != nil {
		return fmt.Errorf("create artifact: %w", err)
	}
	return nil
}

// GetArtifact retrieves a single artifact by ID.
func (db *DB) GetArtifact(id string) (*models.Artifact, error) {
	row := db.conn.QueryRow(
		`SELECT id, case_id, type, source, collection_method, collector_version,
		 privileges_used, sha256, compression, size_raw, size_compressed, collected_at, blob_path
		 FROM artifacts WHERE id = ?`, id,
	)
	return scanArtifact(row)
}

// FindArtifactByFingerprint retrieves an existing artifact that matches the
// same case, type, source, and content hash.
func (db *DB) FindArtifactByFingerprint(caseID, artifactType, source, sha256 string) (*models.Artifact, error) {
	row := db.conn.QueryRow(
		`SELECT id, case_id, type, source, collection_method, collector_version,
		 privileges_used, sha256, compression, size_raw, size_compressed, collected_at, blob_path
		 FROM artifacts
		 WHERE case_id = ? AND type = ? AND source = ? AND sha256 = ?
		 ORDER BY collected_at DESC
		 LIMIT 1`,
		caseID, artifactType, source, sha256,
	)

	artifact, err := scanArtifact(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return artifact, nil
}

// ListArtifacts returns paginated artifacts for a case.
func (db *DB) ListArtifacts(caseID string, limit, offset int) ([]models.Artifact, int, error) {
	return db.ListArtifactsByType(caseID, "", limit, offset)
}

// ListArtifactsByType returns paginated artifacts for a case, optionally
// filtered to a specific artifact type.
func (db *DB) ListArtifactsByType(caseID, artifactType string, limit, offset int) ([]models.Artifact, int, error) {
	if strings.EqualFold(strings.TrimSpace(artifactType), "mft") {
		return []models.Artifact{}, 0, nil
	}

	var total int
	var err error
	if artifactType != "" {
		err = db.conn.QueryRow(
			`SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND type = ? AND type <> 'mft'`,
			caseID, artifactType,
		).Scan(&total)
	} else {
		err = db.conn.QueryRow(
			`SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND type <> 'mft'`,
			caseID,
		).Scan(&total)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("count artifacts: %w", err)
	}

	var rows *sql.Rows
	if artifactType != "" {
		rows, err = db.conn.Query(
			`SELECT id, case_id, type, source, collection_method, collector_version,
			 privileges_used, sha256, compression, size_raw, size_compressed, collected_at, blob_path
			 FROM artifacts
			 WHERE case_id = ? AND type = ? AND type <> 'mft'
			 ORDER BY collected_at DESC LIMIT ? OFFSET ?`,
			caseID, artifactType, limit, offset,
		)
	} else {
		rows, err = db.conn.Query(
			`SELECT id, case_id, type, source, collection_method, collector_version,
			 privileges_used, sha256, compression, size_raw, size_compressed, collected_at, blob_path
			 FROM artifacts
			 WHERE case_id = ? AND type <> 'mft'
			 ORDER BY collected_at DESC LIMIT ? OFFSET ?`,
			caseID, limit, offset,
		)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("list artifacts: %w", err)
	}
	defer rows.Close()

	var artifacts []models.Artifact
	for rows.Next() {
		a, err := scanArtifactRows(rows)
		if err != nil {
			return nil, 0, err
		}
		artifacts = append(artifacts, *a)
	}
	return artifacts, total, rows.Err()
}

// FindArtifactBySourceState retrieves the most recent artifact previously
// collected from the same source path when the source file's size and mtime
// have not changed.
func (db *DB) FindArtifactBySourceState(caseID, artifactType, source string, sourceSize int64, sourceModTime time.Time) (*models.Artifact, error) {
	row := db.conn.QueryRow(
		`SELECT a.id, a.case_id, a.type, a.source, a.collection_method, a.collector_version,
		 a.privileges_used, a.sha256, a.compression, a.size_raw, a.size_compressed, a.collected_at, a.blob_path
		 FROM artifact_source_cache c
		 JOIN artifacts a ON a.id = c.artifact_id
		 WHERE c.case_id = ? AND c.artifact_type = ? AND c.source = ? AND c.source_size = ? AND c.source_mod_time = ?
		 LIMIT 1`,
		caseID, artifactType, source, sourceSize, sourceModTime.UTC().Format(time.RFC3339Nano),
	)

	artifact, err := scanArtifact(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return artifact, nil
}

// UpsertArtifactSourceState records the latest observed size and mtime for a
// collected source path so future runs can skip unchanged files before reading
// or compressing them again.
func (db *DB) UpsertArtifactSourceState(caseID, artifactType, source string, sourceSize int64, sourceModTime time.Time, artifact *models.Artifact) error {
	_, err := db.conn.Exec(
		`INSERT INTO artifact_source_cache (
		 case_id, artifact_type, source, source_size, source_mod_time, artifact_id, sha256, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(case_id, artifact_type, source) DO UPDATE SET
		 source_size = excluded.source_size,
		 source_mod_time = excluded.source_mod_time,
		 artifact_id = excluded.artifact_id,
		 sha256 = excluded.sha256,
		 updated_at = excluded.updated_at`,
		caseID,
		artifactType,
		source,
		sourceSize,
		sourceModTime.UTC().Format(time.RFC3339Nano),
		artifact.ID,
		artifact.SHA256,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("upsert artifact source cache: %w", err)
	}
	return nil
}

var defaultParsableArtifactTypes = []string{
	"evtx",
	"powershell_logs",
	"prefetch",
	"lnk",
	"jumplist_automatic",
	"jumplist_custom",
	"amcache",
	"shimcache",
	"defender_log",
	"defender_mplog",
	"defender_history",
}

// ListArtifactsMissingEvents returns parsable artifacts for a case that do not
// yet have indexed events. It is used to prepare search and timeline views
// without issuing a per-artifact lookup.
func (db *DB) ListArtifactsMissingEvents(caseID string, limit int) ([]models.Artifact, error) {
	return db.ListArtifactsMissingEventsByTypes(caseID, limit)
}

// ListArtifactsMissingEventsByTypes returns artifacts for a case that do not
// yet have indexed events, optionally constrained to specific artifact types.
func (db *DB) ListArtifactsMissingEventsByTypes(caseID string, limit int, artifactTypes ...string) ([]models.Artifact, error) {
	types := artifactTypes
	if len(types) == 0 {
		types = defaultParsableArtifactTypes
	}

	placeholders := make([]string, len(types))
	args := make([]interface{}, 0, len(types)+2)
	args = append(args, caseID)
	for i, artifactType := range types {
		placeholders[i] = "?"
		args = append(args, artifactType)
	}

	query := fmt.Sprintf(`SELECT a.id, a.case_id, a.type, a.source, a.collection_method, a.collector_version,
		 a.privileges_used, a.sha256, a.compression, a.size_raw, a.size_compressed, a.collected_at, a.blob_path
		 FROM artifacts a
		 WHERE a.case_id = ?
		   AND a.type IN (%s)
		   AND NOT EXISTS (
		     SELECT 1
		     FROM events e
		     WHERE e.artifact_id = a.id
		     LIMIT 1
		   )
		 ORDER BY a.collected_at DESC`, strings.Join(placeholders, ", "))

	var (
		rows *sql.Rows
		err  error
	)
	if limit > 0 {
		args = append(args, limit)
		rows, err = db.conn.Query(query+` LIMIT ?`, args...)
	} else {
		rows, err = db.conn.Query(query, args...)
	}
	if err != nil {
		return nil, fmt.Errorf("list artifacts missing events: %w", err)
	}
	defer rows.Close()

	var artifacts []models.Artifact
	for rows.Next() {
		a, err := scanArtifactRows(rows)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, *a)
	}
	return artifacts, rows.Err()
}

func scanArtifact(row *sql.Row) (*models.Artifact, error) {
	var a models.Artifact
	var collectedAt string
	if err := row.Scan(
		&a.ID, &a.CaseID, &a.Type, &a.Source, &a.CollectionMethod, &a.CollectorVersion,
		&a.PrivilegesUsed, &a.SHA256, &a.Compression, &a.SizeRaw, &a.SizeCompressed,
		&collectedAt, &a.BlobPath,
	); err != nil {
		return nil, fmt.Errorf("scan artifact: %w", err)
	}
	var err error
	a.CollectedAt, err = time.Parse(time.RFC3339Nano, collectedAt)
	if err != nil {
		return nil, fmt.Errorf("parse collected_at: %w", err)
	}
	return &a, nil
}

func scanArtifactRows(rows *sql.Rows) (*models.Artifact, error) {
	var a models.Artifact
	var collectedAt string
	if err := rows.Scan(
		&a.ID, &a.CaseID, &a.Type, &a.Source, &a.CollectionMethod, &a.CollectorVersion,
		&a.PrivilegesUsed, &a.SHA256, &a.Compression, &a.SizeRaw, &a.SizeCompressed,
		&collectedAt, &a.BlobPath,
	); err != nil {
		return nil, fmt.Errorf("scan artifact row: %w", err)
	}
	var err error
	a.CollectedAt, err = time.Parse(time.RFC3339Nano, collectedAt)
	if err != nil {
		return nil, fmt.Errorf("parse collected_at: %w", err)
	}
	return &a, nil
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// InsertEvent inserts a single event record.
func (db *DB) InsertEvent(e models.Event) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO events (case_id, artifact_id, timestamp, source, event_id, level, channel, provider, computer, message, raw_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.CaseID, e.ArtifactID, e.Timestamp.Format(time.RFC3339Nano),
		e.Source, e.EventID, e.Level, e.Channel, e.Provider, e.Computer,
		e.Message, e.RawData,
	)
	if err != nil {
		return 0, fmt.Errorf("insert event: %w", err)
	}
	return res.LastInsertId()
}

// InsertEventBatch inserts multiple events in a single transaction.
func (db *DB) InsertEventBatch(events []models.Event) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO events (case_id, artifact_id, timestamp, source, event_id, level, channel, provider, computer, message, raw_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return fmt.Errorf("prepare insert event: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.Exec(
			e.CaseID, e.ArtifactID, e.Timestamp.Format(time.RFC3339Nano),
			e.Source, e.EventID, e.Level, e.Channel, e.Provider, e.Computer,
			e.Message, e.RawData,
		)
		if err != nil {
			return fmt.Errorf("insert event batch item: %w", err)
		}
	}

	return tx.Commit()
}

// SearchEvents performs a full-text search on events and returns paginated results.
func (db *DB) SearchEvents(caseID, query, level, source string, limit, offset int) ([]models.Event, int, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, 0, nil
	}

	if isSimpleEventSearchQuery(query) {
		events, total, err := db.searchEventsByLike(caseID, query, level, source, limit, offset)
		if err == nil && total > 0 {
			return events, total, nil
		}
	}

	ftsQuery := buildEventFTSQuery(query)
	conditions := []string{
		"e.case_id = ?",
		"events_fts MATCH ?",
		"e.source NOT LIKE 'mft%' COLLATE NOCASE",
	}
	args := []interface{}{caseID, ftsQuery}

	if level != "" {
		conditions = append(conditions, "e.level = ?")
		args = append(args, level)
	}
	if source != "" {
		conditions = append(conditions, "e.source LIKE ? COLLATE NOCASE")
		args = append(args, "%"+source+"%")
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total matches.
	var total int
	countQuery := fmt.Sprintf(
		`SELECT COUNT(*) FROM events e
		 JOIN events_fts f ON e.id = f.rowid
		 WHERE %s`,
		whereClause,
	)
	err := db.conn.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search events: %w", err)
	}

	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	searchQuery := fmt.Sprintf(
		`SELECT e.id, e.case_id, e.artifact_id, e.timestamp, e.source, e.event_id,
		 e.level, e.channel, e.provider, e.computer, e.message, e.raw_data
		 FROM events e
		 JOIN events_fts f ON e.id = f.rowid
		 WHERE %s
		 ORDER BY rank
		 LIMIT ? OFFSET ?`,
		whereClause,
	)
	rows, err := db.conn.Query(searchQuery, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("search events: %w", err)
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		e, err := scanEventRows(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, *e)
	}
	return events, total, rows.Err()
}

func isSimpleEventSearchQuery(query string) bool {
	upper := strings.ToUpper(query)
	if strings.ContainsAny(query, "\"*():") {
		return false
	}
	return !strings.Contains(upper, " AND ") &&
		!strings.Contains(upper, " OR ") &&
		!strings.Contains(upper, " NOT ") &&
		!strings.Contains(upper, " NEAR ")
}

func buildEventFTSQuery(query string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return query
	}
	if !isSimpleEventSearchQuery(query) {
		return query
	}

	terms := strings.Fields(query)
	if len(terms) == 0 {
		return query
	}

	quotedTerms := make([]string, 0, len(terms))
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		term = strings.ReplaceAll(term, `"`, `""`)
		quotedTerms = append(quotedTerms, `"`+term+`"`)
	}
	if len(quotedTerms) == 0 {
		return query
	}

	return strings.Join(quotedTerms, " AND ")
}

func (db *DB) searchEventsByLike(caseID, query, level, source string, limit, offset int) ([]models.Event, int, error) {
	conditions := []string{
		"case_id = ?",
		"source NOT LIKE 'mft%' COLLATE NOCASE",
	}
	args := []interface{}{caseID}

	if level != "" {
		conditions = append(conditions, "level = ?")
		args = append(args, level)
	}
	if source != "" {
		conditions = append(conditions, "source LIKE ? COLLATE NOCASE")
		args = append(args, "%"+source+"%")
	}

	needle := "%" + query + "%"
	queryCondition := `(message LIKE ? COLLATE NOCASE
		OR raw_data LIKE ? COLLATE NOCASE
		OR source LIKE ? COLLATE NOCASE
		OR provider LIKE ? COLLATE NOCASE
		OR channel LIKE ? COLLATE NOCASE
		OR computer LIKE ? COLLATE NOCASE
		OR CAST(event_id AS TEXT) = ?)`
	conditions = append(conditions, queryCondition)
	args = append(args, needle, needle, needle, needle, needle, needle, query)

	whereClause := strings.Join(conditions, " AND ")

	var total int
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s`, whereClause)
	if err := db.conn.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count like-search events: %w", err)
	}

	queryArgs := append([]interface{}{}, args...)
	searchQuery := fmt.Sprintf(
		`SELECT id, case_id, artifact_id, timestamp, source, event_id,
		 level, channel, provider, computer, message, raw_data
		 FROM events
		 WHERE %s
		 ORDER BY
		   CASE
		     WHEN CAST(event_id AS TEXT) = ? THEN 0
		     WHEN source LIKE ? COLLATE NOCASE THEN 1
		     WHEN provider LIKE ? COLLATE NOCASE THEN 2
		     WHEN message LIKE ? COLLATE NOCASE THEN 3
		     ELSE 4
		   END,
		   timestamp DESC, id DESC
		 LIMIT ? OFFSET ?`,
		whereClause,
	)
	queryArgs = append(queryArgs, query, needle, needle, needle)
	queryArgs = append(queryArgs, limit, offset)

	rows, err := db.conn.Query(searchQuery, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("like-search events: %w", err)
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		e, err := scanEventRows(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, *e)
	}
	return events, total, rows.Err()
}

// GetEvent retrieves a single event by ID.
func (db *DB) GetEvent(id int64) (*models.Event, error) {
	row := db.conn.QueryRow(
		`SELECT id, case_id, artifact_id, timestamp, source, event_id,
		 level, channel, provider, computer, message, raw_data
		 FROM events WHERE id = ?`, id,
	)
	var e models.Event
	var ts string
	if err := row.Scan(
		&e.ID, &e.CaseID, &e.ArtifactID, &ts, &e.Source, &e.EventID,
		&e.Level, &e.Channel, &e.Provider, &e.Computer, &e.Message, &e.RawData,
	); err != nil {
		return nil, fmt.Errorf("scan event: %w", err)
	}
	e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	return &e, nil
}

// GetEventsByTimeRange retrieves events within a time range for a case.
func (db *DB) GetEventsByTimeRange(caseID string, start, end time.Time, limit, offset int) ([]models.Event, int, error) {
	return db.GetEventsByTimeRangeFiltered(caseID, "", start, end, limit, offset)
}

// GetEventsByTimeRangeFiltered retrieves events within a time range for a case,
// optionally filtering by source.
func (db *DB) GetEventsByTimeRangeFiltered(caseID, source string, start, end time.Time, limit, offset int) ([]models.Event, int, error) {
	startStr := start.Format(time.RFC3339Nano)
	endStr := end.Format(time.RFC3339Nano)

	conditions := []string{
		"case_id = ?",
		"timestamp >= ?",
		"timestamp <= ?",
		"source NOT LIKE 'mft%' COLLATE NOCASE",
	}
	args := []interface{}{caseID, startStr, endStr}
	if source != "" {
		conditions = append(conditions, "source LIKE ? COLLATE NOCASE")
		args = append(args, "%"+source+"%")
	}
	whereClause := strings.Join(conditions, " AND ")

	var total int
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s`, whereClause)
	err := db.conn.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count events by time range: %w", err)
	}

	query := fmt.Sprintf(
		`SELECT id, case_id, artifact_id, timestamp, source, event_id,
		 level, channel, provider, computer, message, raw_data
		 FROM events
		 WHERE %s
		 ORDER BY timestamp ASC
		 LIMIT ? OFFSET ?`,
		whereClause,
	)
	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.conn.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("get events by time range: %w", err)
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		e, err := scanEventRows(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, *e)
	}
	return events, total, rows.Err()
}

// ListEventSources returns the distinct event sources for a case.
func (db *DB) ListEventSources(caseID string) ([]string, error) {
	rows, err := db.conn.Query(
		`SELECT DISTINCT source
		 FROM events
		 WHERE case_id = ? AND source <> '' AND source NOT LIKE 'mft%' COLLATE NOCASE
		 ORDER BY source COLLATE NOCASE ASC`,
		caseID,
	)
	if err != nil {
		return nil, fmt.Errorf("list event sources: %w", err)
	}
	defer rows.Close()

	var sources []string
	for rows.Next() {
		var source string
		if err := rows.Scan(&source); err != nil {
			return nil, fmt.Errorf("scan event source: %w", err)
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func scanEventRows(rows *sql.Rows) (*models.Event, error) {
	var e models.Event
	var ts string
	if err := rows.Scan(
		&e.ID, &e.CaseID, &e.ArtifactID, &ts, &e.Source, &e.EventID,
		&e.Level, &e.Channel, &e.Provider, &e.Computer, &e.Message, &e.RawData,
	); err != nil {
		return nil, fmt.Errorf("scan event row: %w", err)
	}
	e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	return &e, nil
}

// ---------------------------------------------------------------------------
// Collection Jobs
// ---------------------------------------------------------------------------

// CreateJob inserts a new collection job.
func (db *DB) CreateJob(j *models.CollectionJob) error {
	var startedAt, completedAt *string
	if j.StartedAt != nil {
		s := j.StartedAt.Format(time.RFC3339Nano)
		startedAt = &s
	}
	if j.CompletedAt != nil {
		s := j.CompletedAt.Format(time.RFC3339Nano)
		completedAt = &s
	}
	stepsJSON, _ := json.Marshal(j.Steps)
	_, err := db.conn.Exec(
		`INSERT INTO collection_jobs (id, case_id, preset, status, progress, started_at, completed_at, error, artifacts_collected, steps)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.ID, j.CaseID, j.Preset, j.Status, j.Progress,
		startedAt, completedAt, j.Error, j.ArtifactsCollected, string(stepsJSON),
	)
	if err != nil {
		return fmt.Errorf("create job: %w", err)
	}
	return nil
}

// GetJob retrieves a single collection job by ID.
func (db *DB) GetJob(id string) (*models.CollectionJob, error) {
	row := db.conn.QueryRow(
		`SELECT id, case_id, preset, status, progress, started_at, completed_at, error, artifacts_collected, steps
		 FROM collection_jobs WHERE id = ?`, id,
	)
	return scanJob(row)
}

// UpdateJobStatus updates the status and timestamp fields of a job.
func (db *DB) UpdateJobStatus(id, status string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var query string
	var args []interface{}

	switch status {
	case "running":
		query = `UPDATE collection_jobs SET status = ?, started_at = ? WHERE id = ?`
		args = []interface{}{status, now, id}
	case "completed", "completed_with_errors", "failed":
		query = `UPDATE collection_jobs SET status = ?, completed_at = ? WHERE id = ?`
		args = []interface{}{status, now, id}
	default:
		query = `UPDATE collection_jobs SET status = ? WHERE id = ?`
		args = []interface{}{status, id}
	}

	res, err := db.conn.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("update job status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateJobProgress updates the progress percentage and step statuses.
func (db *DB) UpdateJobProgress(id string, progress float64, steps []models.JobStep) error {
	stepsJSON, _ := json.Marshal(steps)
	res, err := db.conn.Exec(
		`UPDATE collection_jobs SET progress = ?, steps = ? WHERE id = ?`,
		progress, string(stepsJSON), id,
	)
	if err != nil {
		return fmt.Errorf("update job progress: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListJobs returns all jobs for a given case.
func (db *DB) ListJobs(caseID string) ([]models.CollectionJob, error) {
	rows, err := db.conn.Query(
		`SELECT id, case_id, preset, status, progress, started_at, completed_at, error, artifacts_collected, steps
		 FROM collection_jobs WHERE case_id = ? ORDER BY started_at DESC`, caseID,
	)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer rows.Close()

	var jobs []models.CollectionJob
	for rows.Next() {
		j, err := scanJobRows(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, *j)
	}
	return jobs, rows.Err()
}

func scanJob(row *sql.Row) (*models.CollectionJob, error) {
	var j models.CollectionJob
	var startedAt, completedAt sql.NullString
	var stepsJSON string
	if err := row.Scan(
		&j.ID, &j.CaseID, &j.Preset, &j.Status, &j.Progress,
		&startedAt, &completedAt, &j.Error, &j.ArtifactsCollected, &stepsJSON,
	); err != nil {
		return nil, fmt.Errorf("scan job: %w", err)
	}
	if startedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, startedAt.String)
		j.StartedAt = &t
	}
	if completedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, completedAt.String)
		j.CompletedAt = &t
	}
	_ = json.Unmarshal([]byte(stepsJSON), &j.Steps)
	return &j, nil
}

func scanJobRows(rows *sql.Rows) (*models.CollectionJob, error) {
	var j models.CollectionJob
	var startedAt, completedAt sql.NullString
	var stepsJSON string
	if err := rows.Scan(
		&j.ID, &j.CaseID, &j.Preset, &j.Status, &j.Progress,
		&startedAt, &completedAt, &j.Error, &j.ArtifactsCollected, &stepsJSON,
	); err != nil {
		return nil, fmt.Errorf("scan job row: %w", err)
	}
	if startedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, startedAt.String)
		j.StartedAt = &t
	}
	if completedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, completedAt.String)
		j.CompletedAt = &t
	}
	_ = json.Unmarshal([]byte(stepsJSON), &j.Steps)
	return &j, nil
}

// ---------------------------------------------------------------------------
// YARA Rules
// ---------------------------------------------------------------------------

// CreateRule inserts a new YARA rule.
func (db *DB) CreateRule(r models.YaraRule) error {
	_, err := db.conn.Exec(
		`INSERT INTO yara_rules (id, case_id, name, content, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.ID, r.CaseID, r.Name, r.Content,
		r.CreatedAt.Format(time.RFC3339Nano), r.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	return nil
}

// GetRule retrieves a single YARA rule by ID.
func (db *DB) GetRule(id string) (*models.YaraRule, error) {
	row := db.conn.QueryRow(
		`SELECT id, case_id, name, content, created_at, created_by FROM yara_rules WHERE id = ?`, id,
	)
	var r models.YaraRule
	var createdAt string
	if err := row.Scan(&r.ID, &r.CaseID, &r.Name, &r.Content, &createdAt, &r.CreatedBy); err != nil {
		return nil, fmt.Errorf("scan rule: %w", err)
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return &r, nil
}

// ListRules returns all YARA rules for a case.
func (db *DB) ListRules(caseID string) ([]models.YaraRule, error) {
	rows, err := db.conn.Query(
		`SELECT id, case_id, name, content, created_at, created_by FROM yara_rules WHERE case_id = ? ORDER BY created_at DESC`,
		caseID,
	)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	var rules []models.YaraRule
	for rows.Next() {
		var r models.YaraRule
		var createdAt string
		if err := rows.Scan(&r.ID, &r.CaseID, &r.Name, &r.Content, &createdAt, &r.CreatedBy); err != nil {
			return nil, fmt.Errorf("scan rule row: %w", err)
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// DeleteRule removes a YARA rule by ID.
func (db *DB) DeleteRule(id string) error {
	res, err := db.conn.Exec(`DELETE FROM yara_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---------------------------------------------------------------------------
// YARA Results
// ---------------------------------------------------------------------------

// InsertResult inserts a new YARA scan result.
func (db *DB) InsertResult(r models.YaraResult) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO yara_results (case_id, rule_id, artifact_id, matches, scanned_at)
		 VALUES (?, ?, ?, ?, ?)`,
		r.CaseID, r.RuleID, r.ArtifactID, r.Matches,
		r.ScannedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return 0, fmt.Errorf("insert result: %w", err)
	}
	return res.LastInsertId()
}

// ListResults returns YARA results for a case, optionally filtered by rule_id.
func (db *DB) ListResults(caseID string, ruleID string) ([]models.YaraResult, error) {
	var rows *sql.Rows
	var err error

	if ruleID != "" {
		rows, err = db.conn.Query(
			`SELECT yr.id, yr.case_id, yr.rule_id, r.name, yr.artifact_id,
				COALESCE(a.source, a.blob_path, ''), yr.matches, yr.scanned_at
			 FROM yara_results yr
			 JOIN yara_rules r ON yr.rule_id = r.id
			 LEFT JOIN artifacts a ON yr.artifact_id = a.id
			 WHERE yr.case_id = ? AND yr.rule_id = ?
			 ORDER BY yr.scanned_at DESC`,
			caseID, ruleID,
		)
	} else {
		rows, err = db.conn.Query(
			`SELECT yr.id, yr.case_id, yr.rule_id, r.name, yr.artifact_id,
				COALESCE(a.source, a.blob_path, ''), yr.matches, yr.scanned_at
			 FROM yara_results yr
			 JOIN yara_rules r ON yr.rule_id = r.id
			 LEFT JOIN artifacts a ON yr.artifact_id = a.id
			 WHERE yr.case_id = ?
			 ORDER BY yr.scanned_at DESC`,
			caseID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list results: %w", err)
	}
	defer rows.Close()

	var results []models.YaraResult
	for rows.Next() {
		var r models.YaraResult
		var scannedAt string
		if err := rows.Scan(&r.ID, &r.CaseID, &r.RuleID, &r.RuleName, &r.ArtifactID, &r.ArtifactPath, &r.Matches, &scannedAt); err != nil {
			return nil, fmt.Errorf("scan result row: %w", err)
		}
		r.ScannedAt, _ = time.Parse(time.RFC3339Nano, scannedAt)
		results = append(results, r)
	}
	return results, rows.Err()
}

// ---------------------------------------------------------------------------
// Action Proposals
// ---------------------------------------------------------------------------

// CreateProposal inserts a new action proposal.
func (db *DB) CreateProposal(p models.ActionProposal) error {
	_, err := db.conn.Exec(
		`INSERT INTO action_proposals (id, case_id, type, title, rationale, steps, status, created_at, approved_at, executed_at, result)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.CaseID, p.Type, p.Title, p.Rationale, p.Steps, p.Status,
		p.CreatedAt.Format(time.RFC3339Nano),
		nullTimeStr(p.ApprovedAt), nullTimeStr(p.ExecutedAt),
		p.Result,
	)
	if err != nil {
		return fmt.Errorf("create proposal: %w", err)
	}
	return nil
}

// GetProposal retrieves a single action proposal by ID.
func (db *DB) GetProposal(id string) (*models.ActionProposal, error) {
	row := db.conn.QueryRow(
		`SELECT id, case_id, type, title, rationale, steps, status, created_at, approved_at, executed_at, result
		 FROM action_proposals WHERE id = ?`, id,
	)
	return scanProposal(row)
}

// ListProposals returns all proposals for a case.
func (db *DB) ListProposals(caseID string) ([]models.ActionProposal, error) {
	rows, err := db.conn.Query(
		`SELECT id, case_id, type, title, rationale, steps, status, created_at, approved_at, executed_at, result
		 FROM action_proposals WHERE case_id = ? ORDER BY created_at DESC`,
		caseID,
	)
	if err != nil {
		return nil, fmt.Errorf("list proposals: %w", err)
	}
	defer rows.Close()

	var proposals []models.ActionProposal
	for rows.Next() {
		p, err := scanProposalRows(rows)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, *p)
	}
	return proposals, rows.Err()
}

// UpdateProposalStatus updates a proposal's status and related timestamps.
func (db *DB) UpdateProposalStatus(id, status, result string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var query string
	var args []interface{}

	switch status {
	case "approved":
		query = `UPDATE action_proposals
			SET status = ?, approved_at = COALESCE(approved_at, ?), result = ?
			WHERE id = ?`
		args = []interface{}{status, now, result, id}
	case "executed":
		query = `UPDATE action_proposals SET status = ?, executed_at = ?, result = ? WHERE id = ?`
		args = []interface{}{status, now, result, id}
	default:
		query = `UPDATE action_proposals SET status = ?, result = ? WHERE id = ?`
		args = []interface{}{status, result, id}
	}

	res, err := db.conn.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("update proposal status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanProposal(row *sql.Row) (*models.ActionProposal, error) {
	var p models.ActionProposal
	var createdAt string
	var approvedAt, executedAt sql.NullString
	if err := row.Scan(
		&p.ID, &p.CaseID, &p.Type, &p.Title, &p.Rationale, &p.Steps, &p.Status,
		&createdAt, &approvedAt, &executedAt, &p.Result,
	); err != nil {
		return nil, fmt.Errorf("scan proposal: %w", err)
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if approvedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, approvedAt.String)
		p.ApprovedAt = &t
	}
	if executedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, executedAt.String)
		p.ExecutedAt = &t
	}
	return &p, nil
}

func scanProposalRows(rows *sql.Rows) (*models.ActionProposal, error) {
	var p models.ActionProposal
	var createdAt string
	var approvedAt, executedAt sql.NullString
	if err := rows.Scan(
		&p.ID, &p.CaseID, &p.Type, &p.Title, &p.Rationale, &p.Steps, &p.Status,
		&createdAt, &approvedAt, &executedAt, &p.Result,
	); err != nil {
		return nil, fmt.Errorf("scan proposal row: %w", err)
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if approvedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, approvedAt.String)
		p.ApprovedAt = &t
	}
	if executedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, executedAt.String)
		p.ExecutedAt = &t
	}
	return &p, nil
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

// AppendAuditEntry inserts an audit log entry, computing the entry_hash from
// the previous entry's hash concatenated with the current entry's content.
func (db *DB) AppendAuditEntry(entry models.AuditEntry) (int64, error) {
	// Get the previous hash for this case.
	var prevHash string
	err := db.conn.QueryRow(
		`SELECT entry_hash FROM audit_log WHERE case_id = ? ORDER BY id DESC LIMIT 1`,
		entry.CaseID,
	).Scan(&prevHash)
	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("get prev hash: %w", err)
	}

	entry.PrevHash = prevHash
	entry.Timestamp = time.Now().UTC()

	// Compute entry hash: SHA256(prev_hash + timestamp + actor + action + details).
	hashInput := strings.Join([]string{
		entry.PrevHash,
		entry.Timestamp.Format(time.RFC3339Nano),
		entry.Actor,
		entry.Action,
		entry.Details,
	}, "")
	h := sha256.Sum256([]byte(hashInput))
	entry.EntryHash = fmt.Sprintf("%x", h)

	res, err := db.conn.Exec(
		`INSERT INTO audit_log (case_id, timestamp, actor, action, tool, details, prev_hash, entry_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.CaseID,
		entry.Timestamp.Format(time.RFC3339Nano),
		entry.Actor, entry.Action, entry.Tool, entry.Details,
		entry.PrevHash, entry.EntryHash,
	)
	if err != nil {
		return 0, fmt.Errorf("append audit entry: %w", err)
	}
	return res.LastInsertId()
}

// GetAuditLog retrieves audit log entries for a case with pagination.
func (db *DB) GetAuditLog(caseID string, limit, offset int) ([]models.AuditEntry, error) {
	rows, err := db.conn.Query(
		`SELECT id, case_id, timestamp, actor, action, tool, details, prev_hash, entry_hash
		 FROM audit_log WHERE case_id = ? ORDER BY id ASC LIMIT ? OFFSET ?`,
		caseID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("get audit log: %w", err)
	}
	defer rows.Close()

	var entries []models.AuditEntry
	for rows.Next() {
		var e models.AuditEntry
		var ts string
		if err := rows.Scan(
			&e.ID, &e.CaseID, &ts, &e.Actor, &e.Action, &e.Tool, &e.Details,
			&e.PrevHash, &e.EntryHash,
		); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ---------------------------------------------------------------------------
// Persistence Items
// ---------------------------------------------------------------------------

// InsertPersistenceItem inserts a new persistence mechanism record.
func (db *DB) InsertPersistenceItem(item *models.PersistenceItem) error {
	_, err := db.conn.Exec(
		`INSERT INTO persistence_items (id, case_id, type, location, value, details)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		item.ID, item.CaseID, item.Type, item.Location, item.Value, item.Details,
	)
	if err != nil {
		return fmt.Errorf("insert persistence item: %w", err)
	}
	return nil
}

// ListPersistenceItems returns all persistence items for a case.
func (db *DB) ListPersistenceItems(caseID string) ([]models.PersistenceItem, error) {
	rows, err := db.conn.Query(
		`SELECT id, case_id, type, location, value, details
		 FROM persistence_items WHERE case_id = ? ORDER BY type, location`,
		caseID,
	)
	if err != nil {
		return nil, fmt.Errorf("list persistence items: %w", err)
	}
	defer rows.Close()

	var items []models.PersistenceItem
	for rows.Next() {
		var item models.PersistenceItem
		if err := rows.Scan(&item.ID, &item.CaseID, &item.Type, &item.Location, &item.Value, &item.Details); err != nil {
			return nil, fmt.Errorf("scan persistence item: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func nullTimeStr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339Nano)
	return &s
}
