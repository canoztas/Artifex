// Command mcp runs the Artifex DFIR MCP (Model Context Protocol) server.
//
// It exposes read-only forensic investigation tools to AI agents over JSON-RPC
// 2.0 transported via stdio (stdin/stdout), following the MCP specification.
// All diagnostic output is written to stderr.
//
// Usage:
//
//	artifex-mcp [flags]
//	  -config string  path to the configuration directory (default: executable directory)
//	  -db     string  override path to the SQLite database file
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/artifex/dfir/internal/audit"
	"github.com/artifex/dfir/internal/config"
	"github.com/artifex/dfir/internal/db"
	"github.com/artifex/dfir/internal/evidence"
	"github.com/artifex/dfir/internal/mcp"

	_ "modernc.org/sqlite"
)

func main() {
	logger := log.New(os.Stderr, "[mcp-main] ", log.LstdFlags|log.Lmsgprefix)

	// Parse command-line flags.
	configDir := flag.String("config", defaultConfigDir(), "path to the configuration directory")
	dbPath := flag.String("db", "", "override path to the SQLite database file")
	flag.Parse()

	logger.Println("Artifex DFIR MCP server starting")
	logger.Printf("config directory: %s", *configDir)

	// Load configuration.
	cfg, err := config.Load(*configDir)
	if err != nil {
		logger.Fatalf("load config: %v", err)
	}
	logger.Printf("data directory: %s", cfg.DataDir)

	// Determine database path.
	dbFile := filepath.Join(cfg.DataDir, "artifex.db")
	if *dbPath != "" {
		dbFile = *dbPath
	}
	logger.Printf("database: %s", dbFile)

	// Open database. The MCP server shares the DB with the main API so we
	// open in read-write mode to allow audit log writes and proposal inserts,
	// but the tool handlers themselves only perform reads (except for the
	// four create-only tools).
	database, err := db.Init(dbFile)
	if err != nil {
		logger.Fatalf("open database: %v", err)
	}
	defer database.Close()
	logger.Println("database opened")

	// Initialize evidence store.
	store := evidence.NewStore(cfg.DataDir)
	logger.Println("evidence store initialized")

	// Initialize audit logger.
	auditLogger := audit.NewLogger(database)
	logger.Println("audit logger initialized")

	// Build the API base URL used by MCP tool handlers that proxy through the
	// main HTTP API.
	apiURL := fmt.Sprintf("http://%s:%d", cfg.BindAddress, cfg.APIPort)
	logger.Printf("API URL: %s", apiURL)

	// Create and run the MCP server.
	server := mcp.NewServer(database, store, auditLogger, apiURL)

	// Set up context with signal handling for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Printf("received signal %v, shutting down", sig)
		cancel()
	}()

	logger.Printf("MCP server ready (name=%s version=%s)", mcp.ServerName, mcp.ServerVersion)
	logger.Println("reading JSON-RPC requests from stdin")

	if err := server.Run(ctx); err != nil {
		logger.Fatalf("server error: %v", err)
	}

	logger.Println("MCP server stopped")
}

// defaultConfigDir returns the directory containing the executable, which is
// the conventional location for config.json.
func defaultConfigDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}
