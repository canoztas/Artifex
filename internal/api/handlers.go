package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pickaxe/dfir/internal/db"
	"github.com/pickaxe/dfir/internal/models"
)

var errWorkerUnavailable = errors.New("worker unavailable")

// ---------------------------------------------------------------------------
// JSON response helpers
// ---------------------------------------------------------------------------

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func errorResponse(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

// ---------------------------------------------------------------------------
// Pagination helpers
// ---------------------------------------------------------------------------

func parsePagination(r *http.Request) db.Page {
	p := db.Page{Limit: 100}
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		p.Limit = v
	}
	if p.Limit > 1000 {
		p.Limit = 1000
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		p.Offset = v
	}
	return p
}

// ---------------------------------------------------------------------------
// Case handlers
// ---------------------------------------------------------------------------

func (s *Server) handleCreateCase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		errorResponse(w, http.StatusBadRequest, "name is required")
		return
	}

	c, err := s.db.CreateCaseByName(req.Name, req.Description)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create case")
		return
	}

	s.audit.Log(c.ID, "user", "create_case", "", fmt.Sprintf("created case %q", c.Name))
	jsonResponse(w, http.StatusCreated, c)
}

func (s *Server) handleListCases(w http.ResponseWriter, r *http.Request) {
	cases, err := s.db.ListCases()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list cases")
		return
	}
	jsonResponse(w, http.StatusOK, cases)
}

func (s *Server) handleGetCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := s.db.GetCase(id)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "case not found")
		return
	}
	jsonResponse(w, http.StatusOK, c)
}

func (s *Server) handleUpdateCaseStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	switch req.Status {
	case "active", "closed", "archived":
	default:
		errorResponse(w, http.StatusBadRequest, "status must be active, closed, or archived")
		return
	}

	if err := s.db.UpdateCaseStatus(id, req.Status); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to update case status")
		return
	}

	s.audit.Log(id, "user", "update_case_status", "", fmt.Sprintf("status changed to %s", req.Status))
	jsonResponse(w, http.StatusOK, map[string]string{"status": req.Status})
}

func (s *Server) handleDeleteCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.db.DeleteCase(id); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to delete case")
		return
	}
	s.audit.Log(id, "user", "delete_case", "", fmt.Sprintf("deleted case %s", id))
	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------------------------------------------------------------------------
// Collection handlers
// ---------------------------------------------------------------------------

func (s *Server) handleStartCollection(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")

	var cfg models.CollectionConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cfg.CaseID = caseID
	if cfg.Preset == "" {
		cfg.Preset = "standard"
	}
	if cfg.Preset != "standard" && cfg.Preset != "deep" {
		errorResponse(w, http.StatusBadRequest, "preset must be standard or deep")
		return
	}

	// Forward the request to the collector service.
	payload, _ := json.Marshal(cfg)
	collectorReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		s.collectorURL+"/collect", bytes.NewReader(payload))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to build collector request")
		return
	}
	collectorReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(collectorReq)
	if err != nil {
		errorResponse(w, http.StatusBadGateway, "collector service unavailable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		errorResponse(w, http.StatusBadGateway, "collector returned error: "+string(body))
		return
	}

	var job models.CollectionJob
	json.NewDecoder(resp.Body).Decode(&job)

	s.audit.Log(caseID, "user", "start_collection", "", fmt.Sprintf("started %s collection job %s", cfg.Preset, job.ID))
	jsonResponse(w, http.StatusAccepted, job)
}

func (s *Server) handleListCollections(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	jobs, err := s.db.ListJobs(caseID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list collection jobs")
		return
	}
	jsonResponse(w, http.StatusOK, jobs)
}

func (s *Server) handleGetCollectionJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobId")
	job, err := s.db.GetJob(jobID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "collection job not found")
		return
	}
	jsonResponse(w, http.StatusOK, job)
}

// ---------------------------------------------------------------------------
// Artifact handlers
// ---------------------------------------------------------------------------

func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	page := parsePagination(r)

	artifacts, total, err := s.db.ListArtifacts(caseID, page.Limit, page.Offset)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list artifacts")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"data":     artifacts,
		"total":    total,
		"has_more": page.Offset+page.Limit < total,
	})
}

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	artifactID := r.PathValue("artifactId")
	artifact, err := s.db.GetArtifact(artifactID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "artifact not found")
		return
	}
	jsonResponse(w, http.StatusOK, artifact)
}

func (s *Server) handleGetArtifactContent(w http.ResponseWriter, r *http.Request) {
	artifactID := r.PathValue("artifactId")
	artifact, err := s.db.GetArtifact(artifactID)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "artifact not found")
		return
	}

	var offset, length int64
	totalSize := artifact.SizeRaw

	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		start, end, ok := parseRangeHeader(rangeHeader, totalSize)
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", totalSize))
			errorResponse(w, http.StatusRequestedRangeNotSatisfiable, "invalid range")
			return
		}
		offset = start
		length = end - start + 1
	} else {
		if v, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64); err == nil && v >= 0 {
			offset = v
		}
		length = totalSize - offset
		if v, err := strconv.ParseInt(r.URL.Query().Get("length"), 10, 64); err == nil && v > 0 {
			length = v
		}
	}

	if offset >= totalSize {
		offset = totalSize
		length = 0
	}
	if offset+length > totalSize {
		length = totalSize - offset
	}

	data, err := s.store.RetrieveChunk(artifact.CaseID, artifact.SHA256, offset, length)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read artifact content")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(data)), 10))
	if rangeHeader != "" {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+int64(len(data))-1, totalSize))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Write(data)
}

func parseRangeHeader(header string, totalSize int64) (int64, int64, bool) {
	if !strings.HasPrefix(header, "bytes=") {
		return 0, 0, false
	}
	rangeSpec := strings.TrimPrefix(header, "bytes=")
	parts := strings.SplitN(rangeSpec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	var start, end int64
	var err error
	if parts[0] == "" {
		end = totalSize - 1
		suffix, e := strconv.ParseInt(parts[1], 10, 64)
		if e != nil || suffix <= 0 {
			return 0, 0, false
		}
		start = totalSize - suffix
		if start < 0 {
			start = 0
		}
	} else {
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil || start < 0 {
			return 0, 0, false
		}
		if parts[1] == "" {
			end = totalSize - 1
		} else {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return 0, 0, false
			}
		}
	}
	if start > end || start >= totalSize {
		return 0, 0, false
	}
	if end >= totalSize {
		end = totalSize - 1
	}
	return start, end, true
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

func (s *Server) handleSearchEvents(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	if err := s.ensureCaseEventsIndexed(caseID); err != nil {
		if errors.Is(err, errWorkerUnavailable) {
			log.Printf("[api] event indexing skipped for case %s: %v", caseID, err)
		} else {
			errorResponse(w, http.StatusBadGateway, "failed to prepare case events: "+err.Error())
			return
		}
	}
	page := parsePagination(r)
	query := r.URL.Query().Get("q")
	level := strings.TrimSpace(r.URL.Query().Get("level"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))

	if query != "" {
		events, total, err := s.db.SearchEvents(caseID, query, level, source, page.Limit, page.Offset)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to search events")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"data":     events,
			"total":    total,
			"has_more": page.Offset+page.Limit < total,
		})
		return
	}

	// No query — return all events in time range
	events, total, err := s.db.GetEventsByTimeRange(caseID,
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Now().Add(24*time.Hour),
		page.Limit, page.Offset)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list events")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"data":     events,
		"total":    total,
		"has_more": page.Offset+page.Limit < total,
	})
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventId")
	eid, err := strconv.ParseInt(eventID, 10, 64)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid event ID")
		return
	}
	event, err := s.db.GetEvent(eid)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "event not found")
		return
	}
	jsonResponse(w, http.StatusOK, event)
}

// ---------------------------------------------------------------------------
// Timeline handler
// ---------------------------------------------------------------------------

func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	if err := s.ensureCaseEventsIndexed(caseID); err != nil {
		if errors.Is(err, errWorkerUnavailable) {
			log.Printf("[api] timeline indexing skipped for case %s: %v", caseID, err)
		} else {
			errorResponse(w, http.StatusBadGateway, "failed to prepare case timeline: "+err.Error())
			return
		}
	}
	page := parsePagination(r)

	start := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Now().Add(24 * time.Hour)

	if startStr := r.URL.Query().Get("start"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			start = t
		}
	}
	if endStr := r.URL.Query().Get("end"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			end = t
		}
	}

	events, total, err := s.db.GetEventsByTimeRange(caseID, start, end, page.Limit, page.Offset)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get timeline")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"data":     events,
		"total":    total,
		"has_more": page.Offset+page.Limit < total,
	})
}

func (s *Server) ensureCaseEventsIndexed(caseID string) error {
	const artifactBatchSize = 250

	offset := 0
	processedAny := false

	for {
		artifacts, total, err := s.db.ListArtifacts(caseID, artifactBatchSize, offset)
		if err != nil {
			return fmt.Errorf("list artifacts: %w", err)
		}

		for _, artifact := range artifacts {
			var route string
			switch artifact.Type {
			case "evtx", "powershell_logs":
				route = "/parse/evtx"
			case "prefetch":
				route = "/parse/prefetch"
			case "amcache":
				route = "/parse/amcache"
			case "shimcache":
				route = "/parse/shimcache"
			default:
				continue
			}

			var existing int
			if err := s.db.Conn().QueryRow(
				`SELECT COUNT(*) FROM events WHERE artifact_id = ?`,
				artifact.ID,
			).Scan(&existing); err != nil {
				return fmt.Errorf("count artifact events %s: %w", artifact.ID, err)
			}
			if existing > 0 {
				continue
			}

			if err := s.postWorkerJSON(route, map[string]interface{}{
				"artifact_id": artifact.ID,
				"case_id":     artifact.CaseID,
				"blob_path":   artifact.BlobPath,
			}); err != nil {
				return fmt.Errorf("parse artifact %s (%s): %w", artifact.ID, artifact.Type, err)
			}
			processedAny = true
		}

		offset += len(artifacts)
		if offset >= total || len(artifacts) == 0 {
			break
		}
	}

	if processedAny {
		if err := s.postWorkerJSON("/timeline/build", map[string]interface{}{
			"case_id": caseID,
		}); err != nil {
			return fmt.Errorf("build timeline: %w", err)
		}
	}

	return nil
}

func (s *Server) postWorkerJSON(path string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal worker payload: %w", err)
	}

	workerReq, err := http.NewRequest(http.MethodPost, s.workerURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build worker request: %w", err)
	}
	workerReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(workerReq)
	if err != nil {
		return fmt.Errorf("%w: %v", errWorkerUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("worker returned error: %s", string(body))
	}

	return nil
}

// ---------------------------------------------------------------------------
// Persistence handler
// ---------------------------------------------------------------------------

func (s *Server) handleListPersistence(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	items, err := s.db.ListPersistenceItems(caseID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list persistence items")
		return
	}
	jsonResponse(w, http.StatusOK, items)
}

// ---------------------------------------------------------------------------
// Network snapshot handler
// ---------------------------------------------------------------------------

func (s *Server) handleGetNetworkSnapshot(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	// Read the latest network_snapshot artifact content
	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "network_snapshot" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			var snapshot models.NetworkSnapshot
			if err := json.Unmarshal(data, &snapshot); err != nil {
				continue
			}
			jsonResponse(w, http.StatusOK, snapshot)
			return
		}
	}
	errorResponse(w, http.StatusNotFound, "network snapshot not found")
}

// ---------------------------------------------------------------------------
// Process snapshot handler
// ---------------------------------------------------------------------------

func (s *Server) handleGetProcesses(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "process_snapshot" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			var procs []models.ProcessInfo
			if err := json.Unmarshal(data, &procs); err != nil {
				continue
			}
			jsonResponse(w, http.StatusOK, procs)
			return
		}
	}
	errorResponse(w, http.StatusNotFound, "process snapshot not found")
}

// ---------------------------------------------------------------------------
// YARA handlers
// ---------------------------------------------------------------------------

func (s *Server) handleCreateYaraRule(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")

	var req struct {
		Name      string `json:"name"`
		Content   string `json:"content"`
		CreatedBy string `json:"created_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Content) == "" {
		errorResponse(w, http.StatusBadRequest, "name and content are required")
		return
	}
	if req.CreatedBy == "" {
		req.CreatedBy = "user"
	}

	rule, err := s.db.CreateYaraRuleByName(caseID, req.Name, req.Content, req.CreatedBy)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create YARA rule")
		return
	}

	s.audit.Log(caseID, req.CreatedBy, "create_yara_rule", "", fmt.Sprintf("created YARA rule %q", req.Name))
	jsonResponse(w, http.StatusCreated, rule)
}

func (s *Server) handleListYaraRules(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	rules, err := s.db.ListRules(caseID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list YARA rules")
		return
	}
	jsonResponse(w, http.StatusOK, rules)
}

func (s *Server) handleRunYaraScan(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")

	var req struct {
		RuleIDs []string `json:"rule_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.RuleIDs) == 0 {
		errorResponse(w, http.StatusBadRequest, "rule_ids is required")
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"case_id":  caseID,
		"rule_ids": req.RuleIDs,
	})
	workerReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		s.workerURL+"/yara/scan", bytes.NewReader(payload))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to build worker request")
		return
	}
	workerReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(workerReq)
	if err != nil {
		errorResponse(w, http.StatusBadGateway, "worker service unavailable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		errorResponse(w, http.StatusBadGateway, "worker returned error: "+string(body))
		return
	}

	var scanResult json.RawMessage
	json.NewDecoder(resp.Body).Decode(&scanResult)

	s.audit.Log(caseID, "user", "run_yara_scan", "", fmt.Sprintf("started YARA scan with %d rules", len(req.RuleIDs)))
	jsonResponse(w, http.StatusAccepted, scanResult)
}

func (s *Server) handleGetYaraResults(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	results, err := s.db.ListResults(caseID, "")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get YARA results")
		return
	}
	jsonResponse(w, http.StatusOK, results)
}

// ---------------------------------------------------------------------------
// Action proposal handlers
// ---------------------------------------------------------------------------

func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	actions, err := s.db.ListProposals(caseID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list actions")
		return
	}
	jsonResponse(w, http.StatusOK, actions)
}

func (s *Server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	actionID := r.PathValue("actionId")

	action, err := s.db.GetProposal(actionID)
	if err != nil || action.CaseID != caseID {
		errorResponse(w, http.StatusNotFound, "action not found")
		return
	}
	if action.Status != "pending" {
		errorResponse(w, http.StatusConflict, "action is not in pending status")
		return
	}

	now := time.Now().UTC()
	action.Status = "approved"
	action.ApprovedAt = &now
	if err := s.db.UpdateProposalStatus(action.ID, action.Status, ""); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to approve action")
		return
	}

	s.audit.Log(caseID, "user", "approve_action", "", fmt.Sprintf("approved action %s: %s", actionID, action.Title))
	jsonResponse(w, http.StatusOK, action)
}

func (s *Server) handleRejectAction(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	actionID := r.PathValue("actionId")

	action, err := s.db.GetProposal(actionID)
	if err != nil || action.CaseID != caseID {
		errorResponse(w, http.StatusNotFound, "action not found")
		return
	}
	if action.Status != "pending" {
		errorResponse(w, http.StatusConflict, "action is not in pending status")
		return
	}

	action.Status = "rejected"
	if err := s.db.UpdateProposalStatus(action.ID, action.Status, ""); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to reject action")
		return
	}

	s.audit.Log(caseID, "user", "reject_action", "", fmt.Sprintf("rejected action %s: %s", actionID, action.Title))
	jsonResponse(w, http.StatusOK, action)
}

func (s *Server) handleExecuteAction(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	actionID := r.PathValue("actionId")

	action, err := s.db.GetProposal(actionID)
	if err != nil || action.CaseID != caseID {
		errorResponse(w, http.StatusNotFound, "action not found")
		return
	}
	if action.Status != "approved" {
		errorResponse(w, http.StatusConflict, "action must be approved before execution")
		return
	}

	now := time.Now().UTC()
	action.Status = "executed"
	action.ExecutedAt = &now

	payload, _ := json.Marshal(map[string]interface{}{
		"case_id":   caseID,
		"action_id": actionID,
		"type":      action.Type,
		"steps":     action.Steps,
	})
	workerReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		s.workerURL+"/actions/execute", bytes.NewReader(payload))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to build worker request")
		return
	}
	workerReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(workerReq)
	if err != nil {
		s.db.UpdateProposalStatus(action.ID, "executed", "execution failed: worker unavailable")
		errorResponse(w, http.StatusBadGateway, "worker service unavailable")
		return
	}
	defer resp.Body.Close()

	resultBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	result := string(resultBody)

	if resp.StatusCode >= 300 {
		s.db.UpdateProposalStatus(action.ID, "executed", "execution failed: "+result)
		errorResponse(w, http.StatusBadGateway, "worker execution failed: "+result)
		return
	}

	if err := s.db.UpdateProposalStatus(action.ID, "executed", result); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to record action result")
		return
	}

	s.audit.Log(caseID, "user", "execute_action", "", fmt.Sprintf("executed action %s: %s", actionID, action.Title))
	jsonResponse(w, http.StatusOK, action)
}

// ---------------------------------------------------------------------------
// Audit log handler
// ---------------------------------------------------------------------------

func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	page := parsePagination(r)

	entries, err := s.db.GetAuditLog(caseID, page.Limit, page.Offset)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get audit log")
		return
	}
	jsonResponse(w, http.StatusOK, entries)
}

// ---------------------------------------------------------------------------
// Registry handlers
// ---------------------------------------------------------------------------

func (s *Server) handleReadRegistry(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")
	regPath := r.URL.Query().Get("path")
	if regPath == "" {
		errorResponse(w, http.StatusBadRequest, "path query parameter is required")
		return
	}

	// Read from stored registry artifacts
	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "registry_persistence" || a.Type == "extended_registry" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			var keys []models.RegistryKeyValue
			if err := json.Unmarshal(data, &keys); err != nil {
				continue
			}
			var matching []models.RegistryKeyValue
			for _, k := range keys {
				if strings.Contains(strings.ToLower(k.Path), strings.ToLower(regPath)) {
					matching = append(matching, k)
				}
			}
			if len(matching) > 0 {
				jsonResponse(w, http.StatusOK, matching)
				return
			}
		}
	}
	jsonResponse(w, http.StatusOK, []models.RegistryKeyValue{})
}

func (s *Server) handleSearchRegistry(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")

	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Query) == "" {
		errorResponse(w, http.StatusBadRequest, "query is required")
		return
	}

	query := strings.ToLower(req.Query)
	var results []models.RegistryKeyValue

	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "registry_persistence" || a.Type == "extended_registry" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			var keys []models.RegistryKeyValue
			if err := json.Unmarshal(data, &keys); err != nil {
				continue
			}
			for _, k := range keys {
				if strings.Contains(strings.ToLower(k.Path), query) ||
					strings.Contains(strings.ToLower(k.Name), query) ||
					strings.Contains(strings.ToLower(k.Data), query) {
					results = append(results, k)
				}
			}
		}
	}

	s.audit.Log(caseID, "user", "search_registry", "", fmt.Sprintf("searched registry for %q", req.Query))
	jsonResponse(w, http.StatusOK, results)
}
