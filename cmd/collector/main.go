package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/artifex/dfir/internal/audit"
	"github.com/artifex/dfir/internal/collector"
	"github.com/artifex/dfir/internal/config"
	"github.com/artifex/dfir/internal/db"
	"github.com/artifex/dfir/internal/evidence"
	"github.com/artifex/dfir/internal/models"
	"github.com/google/uuid"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Artifex Collector Service starting...")

	cfg, err := config.Load(".")
	if err != nil {
		log.Printf("Warning: could not load config, using defaults: %v", err)
		cfg = config.DefaultConfig()
	}

	if cfg.BindAddress != "127.0.0.1" {
		log.Fatal("Security: bind address must be 127.0.0.1")
	}

	database, err := db.Init(fmt.Sprintf("%s/artifex.db", cfg.DataDir))
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	store := evidence.NewStore("evidence")
	auditLog := audit.NewLogger(database)
	coll := collector.New(store, database, cfg)

	mux := http.NewServeMux()

	// POST /collect - start a collection job
	mux.HandleFunc("POST /collect", func(w http.ResponseWriter, r *http.Request) {
		var collCfg models.CollectionConfig
		if err := json.NewDecoder(r.Body).Decode(&collCfg); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		if collCfg.CaseID == "" {
			http.Error(w, `{"error":"case_id is required"}`, http.StatusBadRequest)
			return
		}
		if collCfg.Preset == "" {
			collCfg.Preset = "standard"
		}
		if collCfg.TimeRangeHours == 0 {
			collCfg.TimeRangeHours = 72
		}

		now := time.Now()
		job := &models.CollectionJob{
			ID:        uuid.New().String(),
			CaseID:    collCfg.CaseID,
			Preset:    collCfg.Preset,
			Status:    "pending",
			Progress:  0,
			StartedAt: &now,
		}

		if err := database.CreateJob(job); err != nil {
			log.Printf("Error creating job: %v", err)
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		// Run collection asynchronously
		go func() {
			if err := coll.RunPreset(job, collCfg); err != nil {
				log.Printf("Collection job %s failed: %v", job.ID, err)
			}
		}()

		_ = auditLog.Log(collCfg.CaseID, "collector", "collection_started",
			"start_collection", fmt.Sprintf("preset=%s job_id=%s", collCfg.Preset, job.ID))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(job)
	})

	// GET /collect/{jobId} - get collection status
	mux.HandleFunc("GET /collect/{jobId}", func(w http.ResponseWriter, r *http.Request) {
		jobID := r.PathValue("jobId")
		job, err := database.GetJob(jobID)
		if err != nil {
			http.Error(w, `{"error":"job not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(job)
	})

	// GET /health
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"collector"}`))
	})

	addr := fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.CollectorPort)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down collector service...")
		server.Close()
	}()

	log.Printf("Collector service listening on %s", addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
