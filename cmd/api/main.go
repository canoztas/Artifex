package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pickaxe/dfir/internal/api"
	"github.com/pickaxe/dfir/internal/audit"
	"github.com/pickaxe/dfir/internal/db"
	"github.com/pickaxe/dfir/internal/evidence"
	"github.com/pickaxe/dfir/internal/llm"
	"github.com/pickaxe/dfir/internal/models"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	baseDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	cfg, err := loadConfig(filepath.Join(baseDir, "config.json"))
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.APIPort == 0 {
		cfg.APIPort = 8080
	}
	if cfg.BindAddress == "" {
		cfg.BindAddress = "127.0.0.1"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(baseDir, "data")
	}
	if cfg.CollectorPort == 0 {
		cfg.CollectorPort = 8081
	}
	if cfg.WorkerPort == 0 {
		cfg.WorkerPort = 8083
	}

	dbDir := cfg.DataDir
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	evidenceDir := filepath.Join(baseDir, "evidence")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}

	// Initialize database.
	dbPath := filepath.Join(dbDir, "pickaxe.db")
	database, err := db.Init(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	log.Printf("database initialized at %s", dbPath)

	// Initialize evidence store.
	store := evidence.NewStore(evidenceDir)
	log.Printf("evidence store initialized at %s", evidenceDir)

	// Initialize audit logger.
	auditLog := audit.NewLogger(database)
	log.Printf("audit logger initialized")

	// Compute service URLs.
	collectorURL := fmt.Sprintf("http://%s:%d", cfg.BindAddress, cfg.CollectorPort)
	workerURL := fmt.Sprintf("http://%s:%d", cfg.BindAddress, cfg.WorkerPort)

	// Create API server.
	srv := api.NewServer(database, store, auditLog, collectorURL, workerURL)

	// Initialize LLM provider if configured.
	if cfg.LLM.Provider != "" && cfg.LLM.APIKey != "" {
		llmProvider, llmErr := llm.NewProvider(cfg.LLM)
		if llmErr != nil {
			log.Printf("WARNING: LLM provider init failed: %v (agent chat will be unavailable)", llmErr)
		} else {
			srv.SetLLM(llmProvider)
			log.Printf("LLM provider initialized: %s (model: %s)", cfg.LLM.Provider, cfg.LLM.Model)
		}
	} else {
		log.Printf("LLM provider not configured (set provider and api_key in config.json for agent chat)")
	}

	// Top-level mux serves both API and frontend static files.
	topMux := http.NewServeMux()
	topMux.Handle("/api/", srv.Handler())

	// Serve frontend SPA.
	uiDir := filepath.Join(baseDir, "ui", "dist")
	if info, statErr := os.Stat(uiDir); statErr == nil && info.IsDir() {
		fs := http.FileServer(http.Dir(uiDir))
		topMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			cleanURLPath := path.Clean("/" + r.URL.Path)
			relativePath := cleanURLPath[1:]
			if relativePath != "" {
				diskPath := filepath.Join(uiDir, filepath.FromSlash(relativePath))
				if _, err := os.Stat(diskPath); err == nil {
					fs.ServeHTTP(w, r)
					return
				}
			}
			http.ServeFile(w, r, filepath.Join(uiDir, "index.html"))
		})
		log.Printf("serving frontend from %s", uiDir)
	} else {
		log.Printf("frontend not built yet, skipping static file serving (run: cd ui && npm run build)")
	}

	addr := fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.APIPort)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      topMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("Pickaxe API server listening on %s", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %v, shutting down...", sig)
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Println("server stopped gracefully")
	return nil
}

func loadConfig(path string) (*models.AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("config file not found at %s, using defaults", path)
			return &models.AppConfig{}, nil
		}
		return nil, err
	}

	var cfg models.AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
