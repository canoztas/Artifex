// Package collector orchestrates evidence collection for DFIR investigations.
// It coordinates individual source collectors, tracks progress via job steps,
// and stores artifacts through the evidence store and database.
package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/artifex/dfir/internal/collector/sources"
	"github.com/artifex/dfir/internal/models"
	"github.com/google/uuid"
)

// Version is the collector version stamped into every artifact record.
const Version = "0.1.0"

// EvidenceStore abstracts the underlying evidence storage layer (e.g. blob
// store with compression and hashing). Implementations live in the evidence
// package.
type EvidenceStore interface {
	// Store ingests raw bytes and returns the SHA-256, blob path, and
	// compressed size.
	Store(caseID string, data []byte) (sha256, blobPath string, compressedSize int64, err error)
}

// DB abstracts the database layer for recording artifacts and updating jobs.
type DB interface {
	// CreateArtifact persists an artifact record.
	CreateArtifact(a *models.Artifact) error
	// FindArtifactByFingerprint returns an existing artifact with the same
	// case/type/source/content fingerprint when present.
	FindArtifactByFingerprint(caseID, artifactType, source, sha256 string) (*models.Artifact, error)
	// FindArtifactBySourceState returns an existing artifact when the backing
	// source file has not changed since the last collection.
	FindArtifactBySourceState(caseID, artifactType, source string, sourceSize int64, sourceModTime time.Time) (*models.Artifact, error)
	// UpsertArtifactSourceState records the latest observed source metadata for
	// file-backed artifacts.
	UpsertArtifactSourceState(caseID, artifactType, source string, sourceSize int64, sourceModTime time.Time, artifact *models.Artifact) error
	// CreateJob persists a new collection job.
	CreateJob(job *models.CollectionJob) error
	// UpdateJobProgress updates job progress and step statuses.
	UpdateJobProgress(jobID string, progress float64, steps []models.JobStep) error
	// UpdateJobStatus sets the final job status.
	UpdateJobStatus(jobID, status string) error
	// InsertPersistenceItem records a parsed persistence mechanism.
	InsertPersistenceItem(item *models.PersistenceItem) error
}

// Collector orchestrates evidence collection from Windows systems.
type Collector struct {
	store EvidenceStore
	db    DB
	cfg   models.AppConfig
	mu    sync.Mutex
	jobs  map[string]*models.CollectionJob
}

// New creates a new Collector with the given dependencies.
func New(store EvidenceStore, db DB, cfg models.AppConfig) *Collector {
	return &Collector{
		store: store,
		db:    db,
		cfg:   cfg,
		jobs:  make(map[string]*models.CollectionJob),
	}
}

// collectionStep describes a single evidence collection operation.
type collectionStep struct {
	name string
	fn   func(c *Collector, job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc)
}

// progressFunc is called to update a step's status after it completes.
type progressFunc func(stepIdx int, status string, err error)

// standardSteps defines the collection steps for the "standard" preset.
var standardSteps = []collectionStep{
	{"Host Metadata", (*Collector).collectHostMetadata},
	{"Event Logs (EVTX)", (*Collector).collectEventLogs},
	{"Process Snapshot", (*Collector).collectProcessSnapshot},
	{"Service Snapshot", (*Collector).collectServiceSnapshot},
	{"Scheduled Tasks", (*Collector).collectScheduledTasks},
	{"Network Snapshot", (*Collector).collectNetworkSnapshot},
	{"Persistence Registry Keys", (*Collector).collectPersistenceKeys},
	{"Prefetch Files", (*Collector).collectPrefetch},
	{"Shortcut Files (.lnk)", (*Collector).collectShortcuts},
	{"Jump Lists", (*Collector).collectJumpLists},
	{"AmCache", (*Collector).collectAmCache},
	{"ShimCache", (*Collector).collectShimCache},
	{"PowerShell Logs", (*Collector).collectPowerShellLogs},
	{"Defender Logs", (*Collector).collectDefenderLogs},
	{"Filesystem Metadata", (*Collector).collectFilesystemMetadata},
}

// deepExtras are the additional steps for the "deep" preset.
var deepExtras = []collectionStep{
	{"Extended Registry", (*Collector).collectExtendedRegistry},
	{"Memory Acquisition", (*Collector).collectMemory},
}

// RunPreset executes a collection job using the specified preset. It
// orchestrates all collection steps, updating the job's progress as each
// step completes. Individual step failures are logged but do not abort the
// overall job.
func (c *Collector) RunPreset(job *models.CollectionJob, cfg models.CollectionConfig) error {
	steps := make([]collectionStep, len(standardSteps))
	copy(steps, standardSteps)

	if cfg.Preset == "deep" {
		steps = append(steps, deepExtras...)
	}

	// Initialize job steps.
	job.Steps = make([]models.JobStep, len(steps))
	for i, s := range steps {
		job.Steps[i] = models.JobStep{
			Name:   s.name,
			Status: "pending",
		}
	}
	now := time.Now()
	job.Status = "running"
	job.StartedAt = &now

	if err := c.db.UpdateJobProgress(job.ID, job.Progress, job.Steps); err != nil {
		log.Printf("[collector] failed to update initial job state: %v", err)
	}

	c.mu.Lock()
	c.jobs[job.ID] = job
	c.mu.Unlock()

	totalSteps := len(steps)
	completedSteps := 0

	updateProgress := func(stepIdx int, status string, err error) {
		c.mu.Lock()
		defer c.mu.Unlock()

		job.Steps[stepIdx].Status = status
		if err != nil {
			job.Steps[stepIdx].Error = err.Error()
		}
		job.Steps[stepIdx].Progress = 1.0
		if status == "completed" || status == "failed" || status == "skipped" {
			completedSteps++
		}
		job.Progress = float64(completedSteps) / float64(totalSteps)
		_ = c.db.UpdateJobProgress(job.ID, job.Progress, job.Steps)
	}

	for i, step := range steps {
		c.mu.Lock()
		job.Steps[i].Status = "running"
		c.mu.Unlock()
		_ = c.db.UpdateJobProgress(job.ID, job.Progress, job.Steps)

		log.Printf("[collector] step %d/%d: %s", i+1, totalSteps, step.name)
		step.fn(c, job, cfg, i, updateProgress)
	}

	// Finalize job.
	c.mu.Lock()
	done := time.Now()
	job.CompletedAt = &done
	job.Progress = 1.0

	hasFailures := false
	allFailed := true
	for _, s := range job.Steps {
		if s.Status == "failed" {
			hasFailures = true
		} else if s.Status == "completed" {
			allFailed = false
		}
	}

	if allFailed {
		job.Status = "failed"
		job.Error = "all collection steps failed"
	} else if hasFailures {
		job.Status = "completed_with_errors"
	} else {
		job.Status = "completed"
	}
	c.mu.Unlock()

	_ = c.db.UpdateJobStatus(job.ID, job.Status)
	if err := c.rebuildTimeline(job.CaseID); err != nil {
		log.Printf("[collector] timeline rebuild failed for case %s: %v", job.CaseID, err)
	}
	log.Printf("[collector] job %s finished: %s (%d artifacts)", job.ID, job.Status, job.ArtifactsCollected)

	return nil
}

func (c *Collector) recordSourceState(caseID, artifactType, source string, sourceState *sources.SourceState, artifact *models.Artifact) {
	if sourceState == nil || artifact == nil {
		return
	}
	if err := c.db.UpsertArtifactSourceState(caseID, artifactType, source, sourceState.Size, sourceState.ModTime, artifact); err != nil {
		log.Printf("[collector] source-state cache update failed for %s (%s): %v", source, artifactType, err)
	}
}

func (c *Collector) storeCollectedFile(caseID, artifactType, method, privileges string, file sources.CollectedFile) (*models.Artifact, error) {
	if file.State != nil {
		existing, err := c.db.FindArtifactBySourceState(caseID, artifactType, file.Source, file.State.Size, file.State.ModTime)
		if err != nil {
			return nil, fmt.Errorf("check unchanged source: %w", err)
		}
		if existing != nil {
			log.Printf("[collector] unchanged source skipped for case %s: type=%s source=%s", caseID, artifactType, file.Source)
			return existing, nil
		}
	}

	data, err := sources.ReadFile(file.Path)
	if err != nil {
		return nil, fmt.Errorf("read collected file: %w", err)
	}
	return c.storeArtifact(caseID, artifactType, file.Source, method, privileges, data, file.State)
}

// storeArtifact compresses and stores raw artifact data, then records the
// artifact in the database.
func (c *Collector) storeArtifact(caseID, artifactType, source, method, privileges string, data []byte, sourceState *sources.SourceState) (*models.Artifact, error) {
	sha256Hash, blobPath, compressedSize, err := c.store.Store(caseID, data)
	if err != nil {
		return nil, fmt.Errorf("failed to store evidence: %w", err)
	}

	existing, err := c.db.FindArtifactByFingerprint(caseID, artifactType, source, sha256Hash)
	if err != nil {
		return nil, fmt.Errorf("check existing artifact: %w", err)
	}
	if existing != nil {
		c.recordSourceState(caseID, artifactType, source, sourceState, existing)
		log.Printf("[collector] duplicate artifact skipped for case %s: type=%s source=%s sha256=%s",
			caseID, artifactType, source, sha256Hash)
		return existing, nil
	}

	artifact := &models.Artifact{
		ID:               uuid.New().String(),
		CaseID:           caseID,
		Type:             artifactType,
		Source:           source,
		CollectionMethod: method,
		CollectorVersion: Version,
		PrivilegesUsed:   privileges,
		SHA256:           sha256Hash,
		Compression:      "zstd",
		SizeRaw:          int64(len(data)),
		SizeCompressed:   compressedSize,
		CollectedAt:      time.Now(),
		BlobPath:         blobPath,
	}

	if err := c.db.CreateArtifact(artifact); err != nil {
		return nil, fmt.Errorf("failed to record artifact: %w", err)
	}
	c.recordSourceState(caseID, artifactType, source, sourceState, artifact)

	if err := c.postProcessArtifact(artifact); err != nil {
		log.Printf("[collector] post-processing skipped for artifact %s (%s): %v", artifact.ID, artifact.Type, err)
	}

	c.mu.Lock()
	if j, ok := c.jobs[caseID]; ok {
		j.ArtifactsCollected++
	} else {
		// Search by case ID across all jobs.
		for _, j := range c.jobs {
			if j.CaseID == caseID {
				j.ArtifactsCollected++
				break
			}
		}
	}
	c.mu.Unlock()

	return artifact, nil
}

func (c *Collector) workerURL(path string) string {
	return fmt.Sprintf("http://%s:%d%s", c.cfg.BindAddress, c.cfg.WorkerPort, path)
}

func (c *Collector) postJSON(path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.workerURL(path), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("worker returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *Collector) postProcessArtifact(artifact *models.Artifact) error {
	var route string
	switch artifact.Type {
	case "evtx", "powershell_logs":
		route = "/parse/evtx"
	case "prefetch":
		route = "/parse/prefetch"
	case "lnk":
		route = "/parse/lnk"
	case "jumplist_automatic", "jumplist_custom":
		route = "/parse/jumplist"
	case "amcache":
		route = "/parse/amcache"
	case "shimcache":
		route = "/parse/shimcache"
	case "defender_log", "defender_mplog", "defender_history":
		route = "/parse/defender"
	default:
		return nil
	}

	return c.postJSON(route, map[string]any{
		"artifact_id": artifact.ID,
		"case_id":     artifact.CaseID,
		"blob_path":   artifact.BlobPath,
		"source":      artifact.Source,
	})
}

func (c *Collector) rebuildTimeline(caseID string) error {
	return c.postJSON("/timeline/build", map[string]any{
		"case_id": caseID,
	})
}

// ---------------------------------------------------------------------------
// Individual collection step implementations
// ---------------------------------------------------------------------------

func (c *Collector) collectHostMetadata(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	meta, err := sources.CollectHostMetadata()
	if err != nil {
		log.Printf("[collector] host metadata error: %v", err)
		update(stepIdx, "failed", err)
		return
	}

	data, _ := json.MarshalIndent(meta, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "host_metadata", "system_api", "api_query", "standard", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectEventLogs(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	channels := sources.DefaultEVTXChannels
	if len(cfg.CustomChannels) > 0 {
		channels = append(channels, cfg.CustomChannels...)
	}

	hoursBack := cfg.TimeRangeHours
	if hoursBack == 0 {
		hoursBack = 72 // default to 72 hours
	}

	files, err := sources.CollectEVTX(channels, hoursBack)
	if err != nil {
		log.Printf("[collector] EVTX collection error: %v", err)
	}

	stored := 0
	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, "evtx", "wevtutil_export", "admin", f); storeErr != nil {
			log.Printf("[collector] failed to store %s: %v", f.Source, storeErr)
			continue
		}
		stored++
	}

	if stored == 0 && err != nil {
		update(stepIdx, "failed", err)
	} else {
		update(stepIdx, "completed", nil)
	}
}

func (c *Collector) collectProcessSnapshot(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	processes, err := sources.CollectProcesses()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}
	data, _ := json.MarshalIndent(processes, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "process_snapshot", "system_api", "wmi_query", "standard", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectServiceSnapshot(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	services, err := sources.CollectServices()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}
	data, _ := json.MarshalIndent(services, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "service_snapshot", "system_api", "wmi_query", "standard", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectScheduledTasks(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	tasks, err := sources.CollectScheduledTasks()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}
	data, _ := json.MarshalIndent(tasks, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "scheduled_tasks", "system_api", "schtasks_query", "standard", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectNetworkSnapshot(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	snapshot, err := sources.CollectNetworkSnapshot()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "network_snapshot", "system_api", "api_query", "standard", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectPersistenceKeys(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	keys, err := sources.CollectPersistenceKeys()
	if err != nil {
		log.Printf("[collector] persistence key collection error: %v", err)
	}

	data, _ := json.MarshalIndent(keys, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "registry_persistence", "registry", "reg_query", "standard", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}

	// Create persistence item records in the DB for downstream analysis.
	for _, kv := range keys {
		item := &models.PersistenceItem{
			ID:       uuid.New().String(),
			CaseID:   cfg.CaseID,
			Type:     "registry_autorun",
			Location: kv.Path,
			Value:    kv.Data,
			Details:  fmt.Sprintf("%s = %s (%s)", kv.Name, kv.Data, kv.Type),
		}
		_ = c.db.InsertPersistenceItem(item)
	}

	update(stepIdx, "completed", nil)
}

func (c *Collector) collectPrefetch(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	files, err := sources.CollectPrefetch()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}

	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, "prefetch", "file_copy", "admin", f); storeErr != nil {
			log.Printf("[collector] failed to store prefetch %s: %v", f.Source, storeErr)
		}
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectShortcuts(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	files, err := sources.CollectShortcuts()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}

	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, "lnk", "file_copy", "user", f); storeErr != nil {
			log.Printf("[collector] failed to store shortcut %s: %v", f.Source, storeErr)
		}
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectJumpLists(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	files, err := sources.CollectJumpLists()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}

	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, f.Type, "file_copy", "user", f); storeErr != nil {
			log.Printf("[collector] failed to store Jump List %s: %v", f.Source, storeErr)
		}
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectAmCache(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	files, err := sources.CollectAmCache()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}

	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, "amcache", "file_copy", "admin", f); storeErr != nil {
			log.Printf("[collector] failed to store amcache: %v", storeErr)
		}
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectShimCache(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	files, err := sources.CollectShimCache()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}

	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, "shimcache", "registry_export", "admin", f); storeErr != nil {
			log.Printf("[collector] failed to store shimcache: %v", storeErr)
		}
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectPowerShellLogs(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	// Collect PowerShell-specific event log channels. The main Operational
	// channel is also captured in the general EVTX step, but this step
	// ensures the "Windows PowerShell" (classic) channel is also collected.
	channels := []string{
		"Microsoft-Windows-PowerShell/Operational",
		"Windows PowerShell",
	}

	hoursBack := cfg.TimeRangeHours
	if hoursBack == 0 {
		hoursBack = 72
	}

	files, err := sources.CollectEVTX(channels, hoursBack)
	if err != nil {
		log.Printf("[collector] PowerShell log collection error: %v", err)
	}

	stored := 0
	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, "powershell_logs", "wevtutil_export", "admin", f); storeErr != nil {
			log.Printf("[collector] failed to store PowerShell log %s: %v", f.Source, storeErr)
			continue
		}
		stored++
	}

	if stored == 0 && err != nil {
		update(stepIdx, "failed", err)
	} else {
		update(stepIdx, "completed", nil)
	}
}

func (c *Collector) collectDefenderLogs(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	files, err := sources.CollectDefenderLogs()
	if err != nil {
		update(stepIdx, "skipped", err)
		return
	}

	for _, f := range files {
		if _, storeErr := c.storeCollectedFile(cfg.CaseID, f.Type, "file_copy", "admin", f); storeErr != nil {
			log.Printf("[collector] failed to store Defender log %s: %v", f.Source, storeErr)
		}
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectFilesystemMetadata(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	metadata, err := sources.CollectFileSystemMetadata()
	if err != nil {
		update(stepIdx, "failed", err)
		return
	}
	data, _ := json.MarshalIndent(metadata, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "filesystem_metadata", "filesystem", "directory_scan", "standard", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}

// ---------------------------------------------------------------------------
// Deep-preset extras
// ---------------------------------------------------------------------------

// extendedRegistryKeys are additional registry locations examined in deep mode.
var extendedRegistryKeys = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`,
	`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`,
	`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`,
	`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`,
	`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`,
	`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`,
}

func (c *Collector) collectExtendedRegistry(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	var allKeys []models.RegistryKeyValue
	for _, keyPath := range extendedRegistryKeys {
		vals, err := sources.ReadRegistryKey(keyPath)
		if err != nil {
			log.Printf("[collector] extended registry %s: %v", keyPath, err)
			continue
		}
		allKeys = append(allKeys, vals...)
	}

	if len(allKeys) == 0 {
		log.Printf("[collector] no extended registry data collected")
		update(stepIdx, "completed", nil)
		return
	}

	data, _ := json.MarshalIndent(allKeys, "", "  ")
	if _, storeErr := c.storeArtifact(cfg.CaseID, "extended_registry", "registry", "reg_query", "admin", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}

func (c *Collector) collectMemory(job *models.CollectionJob, cfg models.CollectionConfig, stepIdx int, update progressFunc) {
	if !cfg.IncludeMemory {
		update(stepIdx, "skipped", fmt.Errorf("memory acquisition not requested"))
		return
	}
	if !cfg.MemoryApproved {
		update(stepIdx, "skipped", fmt.Errorf("memory acquisition not approved"))
		return
	}

	log.Println("[collector] WARNING: Starting memory acquisition - this is a privileged operation")

	outputPath := filepath.Join(c.cfg.DataDir, "cases", cfg.CaseID, "memory.raw")
	if err := sources.CollectMemory(outputPath, cfg.MemoryApproved); err != nil {
		update(stepIdx, "failed", err)
		return
	}

	data, readErr := sources.ReadFile(outputPath)
	if readErr != nil {
		update(stepIdx, "failed", readErr)
		return
	}

	if _, storeErr := c.storeArtifact(cfg.CaseID, "memory_dump", "physical_memory", "winpmem", "admin_elevated", data, nil); storeErr != nil {
		update(stepIdx, "failed", storeErr)
		return
	}
	update(stepIdx, "completed", nil)
}
