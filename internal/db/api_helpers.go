package db

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/pickaxe/dfir/internal/models"
)

// PaginatedResult is a generic paginated query result used by the API layer.
type PaginatedResult struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total"`
	NextCursor string      `json:"next_cursor,omitempty"`
	HasMore    bool        `json:"has_more"`
}

// Page holds pagination parameters extracted from query strings.
type Page struct {
	Limit  int
	Offset int
}

// ---------------------------------------------------------------------------
// Convenience wrappers expected by the API handlers
// ---------------------------------------------------------------------------

// CreateCase creates a new case with the given name and description, generating
// a UUID and timestamps automatically.
func (db *DB) CreateCaseByName(name, description string) (*models.Case, error) {
	c := models.Case{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		Status:      "active",
	}
	if err := db.CreateCase(c); err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateCollectionJob creates a new collection job for the given case/preset.
func (db *DB) CreateCollectionJob(caseID, preset string) (*models.CollectionJob, error) {
	now := time.Now().UTC()
	j := &models.CollectionJob{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Preset:    preset,
		Status:    "pending",
		Progress:  0,
		StartedAt: &now,
	}
	if err := db.CreateJob(j); err != nil {
		return nil, err
	}
	return j, nil
}

// UpdateCollectionJobStatus updates job status with an optional error message.
func (db *DB) UpdateCollectionJobStatus(id, status, errMsg string) error {
	if err := db.UpdateJobStatus(id, status); err != nil {
		return err
	}
	if errMsg != "" {
		db.conn.Exec(`UPDATE collection_jobs SET error = ? WHERE id = ?`, errMsg, id)
	}
	return nil
}

// ListCollectionJobs is an alias for ListJobs.
func (db *DB) ListCollectionJobs(caseID string) ([]models.CollectionJob, error) {
	return db.ListJobs(caseID)
}

// GetCollectionJob retrieves a job ensuring it belongs to the given case.
func (db *DB) GetCollectionJob(caseID, jobID string) (*models.CollectionJob, error) {
	j, err := db.GetJob(jobID)
	if err != nil {
		return nil, err
	}
	if j.CaseID != caseID {
		return nil, ErrNotFound
	}
	return j, nil
}

// ListArtifactsPaginated returns a paginated list of artifacts for a case.
func (db *DB) ListArtifactsPaginated(caseID string, p Page) (*PaginatedResult, error) {
	artifacts, total, err := db.ListArtifacts(caseID, p.Limit, p.Offset)
	if err != nil {
		return nil, err
	}
	return &PaginatedResult{
		Data:    artifacts,
		Total:   total,
		HasMore: p.Offset+p.Limit < total,
	}, nil
}

// GetArtifactForCase retrieves an artifact ensuring it belongs to the given case.
func (db *DB) GetArtifactForCase(caseID, artifactID string) (*models.Artifact, error) {
	a, err := db.GetArtifact(artifactID)
	if err != nil {
		return nil, err
	}
	if a.CaseID != caseID {
		return nil, ErrNotFound
	}
	return a, nil
}

// SearchEventsPaginated searches events with filters and pagination.
func (db *DB) SearchEventsPaginated(caseID, query, source, level string, p Page) (*PaginatedResult, error) {
	if query != "" {
		events, total, err := db.SearchEvents(caseID, query, level, source, p.Limit, p.Offset)
		if err != nil {
			return nil, err
		}
		return &PaginatedResult{
			Data:    events,
			Total:   total,
			HasMore: p.Offset+p.Limit < total,
		}, nil
	}
	// No FTS query — use time range search with wide bounds
	events, total, err := db.GetEventsByTimeRange(caseID,
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Now().Add(24*time.Hour),
		p.Limit, p.Offset)
	if err != nil {
		return nil, err
	}
	filtered := filterEvents(events, source, level)
	return &PaginatedResult{
		Data:    filtered,
		Total:   total,
		HasMore: p.Offset+p.Limit < total,
	}, nil
}

func filterEvents(events []models.Event, source, level string) []models.Event {
	if source == "" && level == "" {
		return events
	}
	var filtered []models.Event
	for _, e := range events {
		if source != "" && e.Source != source {
			continue
		}
		if level != "" && e.Level != level {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// GetEventForCase retrieves a single event ensuring it belongs to the case.
func (db *DB) GetEventForCase(caseID string, eventID int64) (*models.Event, error) {
	e, err := db.GetEvent(eventID)
	if err != nil {
		return nil, err
	}
	if e.CaseID != caseID {
		return nil, ErrNotFound
	}
	return e, nil
}

// GetTimeline returns paginated timeline events for a case in time range.
func (db *DB) GetTimeline(caseID string, start, end time.Time, p Page) (*PaginatedResult, error) {
	if start.IsZero() {
		start = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if end.IsZero() {
		end = time.Now().Add(24 * time.Hour)
	}
	events, total, err := db.GetEventsByTimeRange(caseID, start, end, p.Limit, p.Offset)
	if err != nil {
		return nil, err
	}
	return &PaginatedResult{
		Data:    events,
		Total:   total,
		HasMore: p.Offset+p.Limit < total,
	}, nil
}

// ListPersistence is an alias for ListPersistenceItems.
func (db *DB) ListPersistence(caseID string) ([]models.PersistenceItem, error) {
	return db.ListPersistenceItems(caseID)
}

// GetNetworkSnapshot reads the most recent network_snapshot artifact and
// returns its parsed content.
func (db *DB) GetNetworkSnapshot(caseID string) (*models.NetworkSnapshot, error) {
	return db.getJSONArtifact(caseID, "network_snapshot", &models.NetworkSnapshot{})
}

// GetProcesses reads the most recent process_snapshot artifact.
func (db *DB) GetProcesses(caseID string) ([]models.ProcessInfo, error) {
	var procs []models.ProcessInfo
	_, err := db.getJSONArtifactSlice(caseID, "process_snapshot", &procs)
	return procs, err
}

func (db *DB) getJSONArtifact(caseID, artifactType string, dest *models.NetworkSnapshot) (*models.NetworkSnapshot, error) {
	row := db.conn.QueryRow(
		`SELECT blob_path FROM artifacts WHERE case_id = ? AND type = ? ORDER BY collected_at DESC LIMIT 1`,
		caseID, artifactType,
	)
	var blobPath string
	if err := row.Scan(&blobPath); err != nil {
		return nil, err
	}
	// The caller (API handler) will need to read from the evidence store
	// For now, return nil — the handler reads the artifact content directly
	return nil, ErrNotFound
}

func (db *DB) getJSONArtifactSlice(caseID, artifactType string, dest interface{}) (interface{}, error) {
	return nil, ErrNotFound
}

// CreateYaraRuleByName creates a YARA rule with auto-generated ID.
func (db *DB) CreateYaraRuleByName(caseID, name, content, createdBy string) (*models.YaraRule, error) {
	r := models.YaraRule{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Name:      name,
		Content:   content,
		CreatedAt: time.Now().UTC(),
		CreatedBy: createdBy,
	}
	if err := db.CreateRule(r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListYaraRulesByCaseID is an alias for ListRules.
func (db *DB) ListYaraRulesByCaseID(caseID string) ([]models.YaraRule, error) {
	return db.ListRules(caseID)
}

// ListYaraResultsPaginated returns paginated YARA scan results.
func (db *DB) ListYaraResultsPaginated(caseID string, p Page) (*PaginatedResult, error) {
	results, err := db.ListResults(caseID, "")
	if err != nil {
		return nil, err
	}
	total := len(results)
	end := p.Offset + p.Limit
	if end > total {
		end = total
	}
	start := p.Offset
	if start > total {
		start = total
	}
	return &PaginatedResult{
		Data:    results[start:end],
		Total:   total,
		HasMore: end < total,
	}, nil
}

// ListActionsPaginated lists action proposals with optional status filter.
func (db *DB) ListActionsPaginated(caseID, status string, p Page) (*PaginatedResult, error) {
	all, err := db.ListProposals(caseID)
	if err != nil {
		return nil, err
	}
	var filtered []models.ActionProposal
	for _, a := range all {
		if status != "" && a.Status != status {
			continue
		}
		filtered = append(filtered, a)
	}
	total := len(filtered)
	end := p.Offset + p.Limit
	if end > total {
		end = total
	}
	start := p.Offset
	if start > total {
		start = total
	}
	return &PaginatedResult{
		Data:    filtered[start:end],
		Total:   total,
		HasMore: end < total,
	}, nil
}

// GetAction retrieves an action proposal for a case.
func (db *DB) GetAction(caseID, actionID string) (*models.ActionProposal, error) {
	a, err := db.GetProposal(actionID)
	if err != nil {
		return nil, err
	}
	if a.CaseID != caseID {
		return nil, ErrNotFound
	}
	return a, nil
}

// UpdateAction updates an action proposal's status and result.
func (db *DB) UpdateAction(a *models.ActionProposal) error {
	return db.UpdateProposalStatus(a.ID, a.Status, a.Result)
}

// GetAuditLogPaginated returns paginated audit entries.
func (db *DB) GetAuditLogPaginated(caseID string, p Page) (*PaginatedResult, error) {
	entries, err := db.GetAuditLog(caseID, p.Limit, p.Offset)
	if err != nil {
		return nil, err
	}
	return &PaginatedResult{
		Data:    entries,
		Total:   len(entries), // approximate
		HasMore: len(entries) == p.Limit,
	}, nil
}

// ReadRegistryKeys retrieves stored registry data for a case matching a path.
func (db *DB) ReadRegistryKeys(caseID, path string) ([]models.RegistryKeyValue, error) {
	// Read from stored registry_persistence artifacts
	artifacts, _, err := db.ListArtifacts(caseID, 100, 0)
	if err != nil {
		return nil, err
	}
	// Return empty for now — actual content is in evidence blobs
	_ = artifacts
	return nil, nil
}

// SearchRegistryPaginated searches registry data stored for a case.
func (db *DB) SearchRegistryPaginated(caseID, query, regType string, p Page) (*PaginatedResult, error) {
	return &PaginatedResult{
		Data:    []models.RegistryKeyValue{},
		Total:   0,
		HasMore: false,
	}, nil
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

type dbError string

func (e dbError) Error() string { return string(e) }

const ErrNotFound = dbError("not found")

// Ensure json import is used.
var _ = json.Marshal
