# Artifex DFIR

Artifex is a Digital Forensics & Incident Response assistant that lets AI models assist with forensic analysis, threat hunting, and incident response on a target endpoint. It includes local artifact collection, event parsing, timeline generation, and MCP-based investigation tooling so models can analyze evidence without direct destructive control of the host.

For now, it only works on Windows.

Service stack:

- A Go API that serves JSON endpoints
- A Go collector that gathers evidence from the host
- A Python worker that parses artifacts, builds timelines, and runs YARA
- A React UI for case-driven investigation
- An MCP server for non-destructive AI access (No modification of any sort except writing and executing YARA rules.)

The design goal is simple: keep evidence collection local, make investigation data easy to search, and let AI assist analysis without giving it direct destructive control over the endpoint.

## Project Status

This repository is an active prototype/MVP, not a finished product.

What works today:

- Case creation, listing, and deletion
- Standard and deep collection presets
- Evidence storage with SHA-256 metadata and zstd compression
- Artifact browsing and chunked artifact reads
- Event indexing and FTS-backed search in SQLite
- Timeline generation from parsed artifacts
- Process, network, persistence, and audit views
- YARA rule storage and creation
- Agent chat and MCP-based forensic access through Anthropic, Gemini, OpenAI, or DeepSeek-backed models

In Progress:

- Some UI and API edges are still inconsistent
- Action Management
- YARA Execution
- Parsing of some artifacts ex. prefetch
- Memory acquisition and extending artifact collection.

## Why Artifex Exists

Most forensic tooling is either heavyweight, expensive, remote-first, or awkward to extend. Artifex is aiming for a different tradeoff:
Artifex is a prototype on how would AI integration on Incident response processes would be. It progresses with our knowledge and effort which may reach to production-ready state one day.

## Architecture

At a high level, the data flow looks like this:

1. The collector gathers host evidence from system.
2. Raw artifacts are stored locally as compressed evidence blobs.
3. The worker parses supported artifacts into normalized events and timelines.
4. The API exposes cases, artifacts, events, timelines, YARA workflows, audit data, and agent chat.
5. The UI talks to the API over configured address. (ex. `http://127.0.0.1:8080/api`) 
6. The MCP server exposes read-oriented investigation tools over stdio.

Main components:

| Component | Purpose |
| --- | --- |
| `cmd/api` | Main API server |
| `cmd/collector` | Windows evidence collection service |
| `cmd/mcp` | MCP server over stdio |
| `worker/main.py` | Parsing, timeline, and YARA worker |
| `ui/` | React + Vite frontend |

## Collected Data

The standard workflow currently includes:

- Host metadata
- Event logs
- Process snapshots
- Service snapshots
- Scheduled tasks
- Network snapshots
- Persistence registry keys
- Prefetch files
- AmCache
- ShimCache
- PowerShell logs
- Defender logs
- Filesystem metadata

The deep preset adds:

- Extended registry collection
- Optional memory acquisition (In-Progress)

## Quick Start

### 1. Prerequisites

Artifex is developed to work on Windows. (For now)

Install:

- Go `1.22+`
- Python `3.10+`
- Node.js `20+`
- npm

Dependencies live in:

- `worker/requirements.txt`
- `ui/package.json`

### 2. Initial setup

From the repo root:

```powershell
scripts\setup.bat
```

This script:

- checks for Go, Python, Node.js, and npm
- creates `data`, `evidence`, `tools`, and `bin`
- downloads Go dependencies
- installs Python worker dependencies
- installs UI dependencies

### 3. Configure the app

Edit `config.json` before running the stack.

Example:

```json
{
  "api_port": 8080,
  "collector_port": 8081,
  "mcp_port": 8082,
  "worker_port": 8083,
  "data_dir": "./data",
  "bind_address": "127.0.0.1",
  "llm": {
    "provider": "gemini",
    "api_key": "YOUR_API_KEY", 
    "model": "gemini-2.5-flash", 
    "max_tokens": 8192,
    "temperature": 0.1,
    "timeout_ms": 100000,
    "retries": 3,
    "redaction_mode": "basic",
    "data_handling_notice": "Evidence data may be sent to a cloud AI provider."
  }
}
```

Important notes:

- the API can start without an LLM, but agent chat will be unavailable
- supported LLM providers are currently `anthropic`, `gemini`, `openai`, and `deepseek`
- the MCP server runs over stdio; `mcp_port` is reserved for future transport support
- Increase timeout duration and max token count for better reasoning. (30k+ token count would give better results. Timeout duration must be increased accordingly.)

Example Anthropic configuration:

```json
{
  "llm": {
    "provider": "anthropic",
    "api_key": "YOUR_ANTHROPIC_API_KEY",
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 4096,
    "temperature": 0.1,
    "timeout_ms": 30000,
    "retries": 3,
    "redaction_mode": "basic",
    "data_handling_notice": "Evidence data may be sent to a cloud AI provider."
  }
}
```

Example OpenAI configuration:

```json
{
  "llm": {
    "provider": "openai",
    "api_key": "YOUR_OPENAI_API_KEY",
    "model": "gpt-4o",
    "max_tokens": 4096,
    "temperature": 0.1,
    "timeout_ms": 30000,
    "retries": 3,
    "redaction_mode": "basic",
    "data_handling_notice": "Evidence data may be sent to a cloud AI provider."
  }
}
```

Example DeepSeek configuration:

```json
{
  "llm": {
    "provider": "deepseek",
    "api_key": "YOUR_DEEPSEEK_API_KEY",
    "model": "deepseek-chat",
    "max_tokens": 4096,
    "temperature": 0.1,
    "timeout_ms": 30000,
    "retries": 3,
    "redaction_mode": "basic",
    "data_handling_notice": "Evidence data may be sent to a cloud AI provider."
  }
}
```

### 4. Build

```powershell
scripts\build.bat
```

This builds:

- `bin\artifex-api.exe`
- `bin\artifex-collector.exe`
- `bin\artifex-mcp.exe`

It also installs missing worker dependencies and builds the frontend.

### 5. Run

```powershell
scripts\run.bat
```

Run this script with administrator privileges to prevent issues on artifact collection.

By default this starts:

- Collector on `127.0.0.1:8081`
- Worker on `127.0.0.1:8083`
- API and UI on `127.0.0.1:8080`

The startup script now launches the full stack in the background, tracks the started PIDs, and checks collector, worker, and API health before reporting success. If the worker fails to come up, inspect:

- `data\worker.log`
- `data\worker.stdout.log`

To stop the full stack cleanly:

```powershell
scripts\stop.bat
```

You can also use:

```powershell
scripts\run.bat stop
```

Then open:

```text
http://127.0.0.1:8080
```

## Running Components Manually

If you want to run the pieces yourself:

### Build Go binaries

```powershell
go build -o bin\artifex-api.exe .\cmd\api\
go build -o bin\artifex-collector.exe .\cmd\collector\
go build -o bin\artifex-mcp.exe .\cmd\mcp\
```

### Install worker and UI dependencies

```powershell
python -m pip install -r worker\requirements.txt
cd ui
npm install
npm run build
```

### Start the collector

```powershell
bin\artifex-collector.exe
```

### Start the worker

From the repo root in another shell:

```powershell
$env:ARTIFEX_DB="$PWD\data\artifex.db"
$env:ARTIFEX_EVIDENCE="$PWD\evidence"
python worker\main.py
```

### Start the API

In another shell:

```powershell
bin\artifex-api.exe
```

## MCP Server

The MCP server is a separate stdio process, this is how AI interacts with the analysis target:

```powershell
bin\artifex-mcp.exe
```

The current tool set is:

| Tool | What it does |
| --- | --- |
| `start_collection` | Starts a new evidence collection job for a case using the `standard` or `deep` preset. |
| `get_collection_status` | Returns job status, progress, and step-level details for a collection run. |
| `list_artifacts` | Lists collected artifacts for a case with metadata such as type, source, hashes, and sizes. |
| `read_artifact` | Reads a chunk of an artifact’s raw content and returns it as base64. |
| `list_event_sources` | Shows which parsed event sources and channels exist for the case, with counts and time ranges. |
| `search_events` | Runs full-text search over normalized events, with pagination and optional time filtering. |
| `get_event` | Retrieves one specific event including its full raw payload. |
| `get_timeline` | Returns chronological events for the case, with pagination and optional time filtering. |
| `read_registry_keys` | Reads collected registry values under a specific registry key path. |
| `search_registry` | Searches collected registry entries under a root path by matching names and data. |
| `yara_scan` | Submits a YARA scan job for a specific artifact using an existing rule. |
| `get_persistence_items` | Returns parsed persistence mechanisms such as autoruns, services, and task-based persistence. |
| `get_execution_artifacts` | Returns execution evidence such as Prefetch, ShimCache, AmCache, UserAssist, and BAM-derived events when present. |
| `get_network_snapshot` | Returns the captured network snapshot, including connections, DNS cache, ARP table, and routes. |
| `list_yara_rules` | Lists YARA rules stored for the case. |
| `create_yara_rule` | Creates and stores a new YARA rule for the case. |
| `get_yara_results` | Returns stored YARA scan results for a rule. |
| `recommend_action` | Creates an advisory response proposal for human review; it does not execute the action. |
| `get_audit_log` | Returns the case audit log, including hash-chained entries for prior activity. |
| `get_process_snapshot` | Returns one of three collected snapshots: `processes`, `services`, or `tasks`. |

Most MCP tools are read-only. The main exceptions are `start_collection`, `create_yara_rule`, `yara_scan`, and `recommend_action`, which create jobs or records but do not directly modify the endpoint.

The intent is still read-oriented investigation. AI-generated actions should remain human-reviewed and explicitly approved.

## Repository Layout

```text
cmd/                 Service entrypoints
internal/            Go packages for API, collector, DB, evidence, MCP, LLM
worker/              Python worker, parsers, timeline builder, YARA scanner
ui/                  React frontend
scripts/             Windows setup, build, and run helpers
bin/                 Built executables
data/                SQLite DB, logs, runtime data
evidence/            Stored evidence blobs
docs/                Project documentation
config.json          Local runtime configuration
PLANS.md             MVP scope and implementation notes
```

## Storage and Runtime Data

Artifex stores its runtime data locally:

- SQLite database in `data\artifex.db`
- Evidence blobs under `evidence\...`
- Worker logs in `data\worker.log` and `data\worker.stdout.log`

Artifacts are tracked with:

- SHA-256 hash
- raw and compressed sizes
- compression type
- collection method
- collector version
- privileges used
- collection timestamp

## API Overview

The HTTP API is mounted under `/api`.

Main route groups include:

- `/api/cases`
- `/api/cases/{caseId}/collections`
- `/api/cases/{caseId}/artifacts`
- `/api/cases/{caseId}/events`
- `/api/cases/{caseId}/timeline`
- `/api/cases/{caseId}/persistence`
- `/api/cases/{caseId}/network-snapshot`
- `/api/cases/{caseId}/yara/...`
- `/api/cases/{caseId}/actions/...`
- `/api/cases/{caseId}/audit`
- `/api/cases/{caseId}/agent/chat`

## Security and Data Handling

Artifex is intentionally localhost-only by default.

Keep these constraints in mind:

- Do not expose this stack directly to a network
- Do not commit real API keys or secrets
- Evidence may be sent to a cloud provider if agent chat is enabled ()
- Review your organization’s data handling requirements before enabling LLM features
- Treat this project as a prototype, do not use this product on real investigations as of now it is not polished enough to provide fully offline integration. 
