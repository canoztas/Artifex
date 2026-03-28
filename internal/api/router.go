package api

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pickaxe/dfir/internal/audit"
	"github.com/pickaxe/dfir/internal/db"
	"github.com/pickaxe/dfir/internal/evidence"
	"github.com/pickaxe/dfir/internal/llm"
)

// Server is the HTTP API server for Pickaxe.
type Server struct {
	db           *db.DB
	store        *evidence.Store
	audit        *audit.Logger
	mux          *http.ServeMux
	collectorURL string
	workerURL    string
	llm          llm.Provider
}

// NewServer creates a new API server with all routes registered.
func NewServer(database *db.DB, store *evidence.Store, auditLog *audit.Logger, collectorURL, workerURL string) *Server {
	s := &Server{
		db:           database,
		store:        store,
		audit:        auditLog,
		mux:          http.NewServeMux(),
		collectorURL: collectorURL,
		workerURL:    workerURL,
	}
	s.registerRoutes()
	return s
}

// SetLLM sets the LLM provider for agent capabilities.
func (s *Server) SetLLM(provider llm.Provider) {
	s.llm = provider
}

// Handler returns the HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = s.corsMiddleware(h)
	h = s.loggingMiddleware(h)
	return h
}

func (s *Server) registerRoutes() {
	// Case management
	s.mux.HandleFunc("POST /api/cases", s.handleCreateCase)
	s.mux.HandleFunc("GET /api/cases", s.handleListCases)
	s.mux.HandleFunc("GET /api/cases/{id}", s.handleGetCase)
	s.mux.HandleFunc("PUT /api/cases/{id}/status", s.handleUpdateCaseStatus)
	s.mux.HandleFunc("DELETE /api/cases/{id}", s.handleDeleteCase)

	// Collection jobs
	s.mux.HandleFunc("POST /api/cases/{caseId}/collections", s.caseValidation(s.handleStartCollection))
	s.mux.HandleFunc("GET /api/cases/{caseId}/collections", s.caseValidation(s.handleListCollections))
	s.mux.HandleFunc("GET /api/cases/{caseId}/collections/{jobId}", s.caseValidation(s.handleGetCollectionJob))

	// Artifacts
	s.mux.HandleFunc("GET /api/cases/{caseId}/artifacts", s.caseValidation(s.handleListArtifacts))
	s.mux.HandleFunc("GET /api/cases/{caseId}/artifacts/{artifactId}", s.caseValidation(s.handleGetArtifact))
	s.mux.HandleFunc("GET /api/cases/{caseId}/artifacts/{artifactId}/content", s.caseValidation(s.handleGetArtifactContent))

	// Events
	s.mux.HandleFunc("GET /api/cases/{caseId}/events", s.caseValidation(s.handleSearchEvents))
	s.mux.HandleFunc("GET /api/cases/{caseId}/events/{eventId}", s.caseValidation(s.handleGetEvent))

	// Timeline
	s.mux.HandleFunc("GET /api/cases/{caseId}/timeline", s.caseValidation(s.handleGetTimeline))

	// Persistence
	s.mux.HandleFunc("GET /api/cases/{caseId}/persistence", s.caseValidation(s.handleListPersistence))

	// Network snapshot
	s.mux.HandleFunc("GET /api/cases/{caseId}/network-snapshot", s.caseValidation(s.handleGetNetworkSnapshot))

	// Processes
	s.mux.HandleFunc("GET /api/cases/{caseId}/processes", s.caseValidation(s.handleGetProcesses))

	// YARA
	s.mux.HandleFunc("POST /api/cases/{caseId}/yara/rules", s.caseValidation(s.handleCreateYaraRule))
	s.mux.HandleFunc("GET /api/cases/{caseId}/yara/rules", s.caseValidation(s.handleListYaraRules))
	s.mux.HandleFunc("POST /api/cases/{caseId}/yara/scan", s.caseValidation(s.handleRunYaraScan))
	s.mux.HandleFunc("GET /api/cases/{caseId}/yara/results", s.caseValidation(s.handleGetYaraResults))

	// Action proposals
	s.mux.HandleFunc("GET /api/cases/{caseId}/actions", s.caseValidation(s.handleListActions))
	s.mux.HandleFunc("POST /api/cases/{caseId}/actions/{actionId}/approve", s.caseValidation(s.handleApproveAction))
	s.mux.HandleFunc("POST /api/cases/{caseId}/actions/{actionId}/reject", s.caseValidation(s.handleRejectAction))
	s.mux.HandleFunc("POST /api/cases/{caseId}/actions/{actionId}/execute", s.caseValidation(s.handleExecuteAction))

	// Audit log
	s.mux.HandleFunc("GET /api/cases/{caseId}/audit", s.caseValidation(s.handleGetAuditLog))

	// Agent chat (LLM-powered analysis)
	s.mux.HandleFunc("POST /api/cases/{caseId}/agent/chat", s.caseValidation(s.handleAgentChat))

	// Registry
	s.mux.HandleFunc("GET /api/cases/{caseId}/registry", s.caseValidation(s.handleReadRegistry))
	s.mux.HandleFunc("POST /api/cases/{caseId}/registry/search", s.caseValidation(s.handleSearchRegistry))
}

// caseValidation wraps a handler to validate the caseId path parameter exists.
func (s *Server) caseValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caseID := r.PathValue("caseId")
		if caseID == "" {
			errorResponse(w, http.StatusBadRequest, "missing case ID")
			return
		}
		_, err := s.db.GetCase(caseID)
		if err != nil {
			errorResponse(w, http.StatusNotFound, "case not found")
			return
		}
		next(w, r)
	}
}

// corsMiddleware adds CORS headers that allow localhost origins.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if isLocalhostOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Range")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLocalhostOrigin checks whether the origin matches a localhost address.
func isLocalhostOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	lower := strings.ToLower(origin)
	return strings.HasPrefix(lower, "http://localhost") ||
		strings.HasPrefix(lower, "https://localhost") ||
		strings.HasPrefix(lower, "http://127.0.0.1") ||
		strings.HasPrefix(lower, "https://127.0.0.1")
}

// loggingMiddleware logs each HTTP request with its method, path, status, and duration.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.statusCode, time.Since(start))
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
