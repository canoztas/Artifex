// Package mcp implements the Model Context Protocol server for the Pickaxe DFIR
// platform. It exposes forensic investigation tools to AI agents over JSON-RPC
// 2.0 transported via stdio, following the MCP specification.
//
// All tools enforce case-level scoping, pagination limits, per-call timeouts,
// and response size caps. The AI agent MUST NOT be able to modify or delete
// evidence, files, or system settings through this interface.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/pickaxe/dfir/internal/audit"
	"github.com/pickaxe/dfir/internal/db"
	"github.com/pickaxe/dfir/internal/evidence"
)

// Quota constants enforced on every tool call.
const (
	MaxRowsPerCall    = 10000
	MaxPageSize       = 1000
	MaxResponseBytes  = 5 * 1024 * 1024 // 5 MB
	ToolCallTimeout   = 30 * time.Second
	ServerName        = "pickaxe-dfir"
	ServerVersion     = "0.1.0"
	ProtocolVersion   = "2024-11-05"
	JSONRPCVersion    = "2.0"
)

// MCPServer handles MCP JSON-RPC requests over stdio.
type MCPServer struct {
	db     *db.DB
	store  *evidence.Store
	audit  *audit.Logger
	apiURL string // Base URL for the collector API (e.g. http://127.0.0.1:8081).
	logger *log.Logger
}

// JSONRPCRequest is a JSON-RPC 2.0 request envelope.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response envelope.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError carries a JSON-RPC error code and message.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool describes a single MCP tool exposed to the agent.
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolCallParams carries the parsed parameters for a tools/call request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolResult is the response payload returned from a tool call.
type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is one piece of content in a tool result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Standard JSON-RPC error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// NewServer creates a new MCP server with the given dependencies.
func NewServer(database *db.DB, store *evidence.Store, auditLogger *audit.Logger, apiURL string) *MCPServer {
	return &MCPServer{
		db:     database,
		store:  store,
		audit:  auditLogger,
		apiURL: apiURL,
		logger: log.New(os.Stderr, "[mcp] ", log.LstdFlags|log.Lmsgprefix),
	}
}

// Run starts the stdio JSON-RPC loop. It reads newline-delimited JSON from
// stdin, dispatches each request, and writes the response to stdout. It blocks
// until stdin is closed or ctx is cancelled.
func (s *MCPServer) Run(ctx context.Context) error {
	s.logger.Println("MCP server starting, reading from stdin")

	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			s.logger.Println("context cancelled, shutting down")
			return ctx.Err()
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				s.logger.Println("stdin closed, shutting down")
				return nil
			}
			return fmt.Errorf("read stdin: %w", err)
		}

		// Parse the JSON-RPC request.
		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      nil,
				Error: &RPCError{
					Code:    CodeParseError,
					Message: fmt.Sprintf("parse error: %v", err),
				},
			}
			if err := writeResponse(writer, resp); err != nil {
				return fmt.Errorf("write parse error response: %w", err)
			}
			continue
		}

		if req.JSONRPC != JSONRPCVersion {
			resp := JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Error: &RPCError{
					Code:    CodeInvalidRequest,
					Message: "unsupported jsonrpc version",
				},
			}
			if err := writeResponse(writer, resp); err != nil {
				return fmt.Errorf("write version error response: %w", err)
			}
			continue
		}

		s.logger.Printf("request: method=%s id=%v", req.Method, req.ID)

		resp := s.dispatch(ctx, &req)
		if err := writeResponse(writer, resp); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
}

// dispatch routes a JSON-RPC request to the appropriate handler.
func (s *MCPServer) dispatch(ctx context.Context, req *JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "notifications/initialized":
		// Client acknowledgement; no response needed for notifications,
		// but since we received it as a request with an ID, acknowledge it.
		return JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Result:  map[string]interface{}{},
		}
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(ctx, req)
	default:
		return JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Error: &RPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			},
		}
	}
}

// handleInitialize responds to the MCP initialize handshake.
func (s *MCPServer) handleInitialize(req *JSONRPCRequest) JSONRPCResponse {
	s.logger.Println("handling initialize")

	result := map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    ServerName,
			"version": ServerVersion,
		},
	}

	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsList returns the full list of available tools and their schemas.
func (s *MCPServer) handleToolsList(req *JSONRPCRequest) JSONRPCResponse {
	s.logger.Println("handling tools/list")

	tools := AllTools()
	result := map[string]interface{}{
		"tools": tools,
	}

	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsCall dispatches a tool invocation with timeout enforcement.
func (s *MCPServer) handleToolsCall(ctx context.Context, req *JSONRPCRequest) JSONRPCResponse {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Error: &RPCError{
				Code:    CodeInvalidParams,
				Message: fmt.Sprintf("invalid tool call params: %v", err),
			},
		}
	}

	s.logger.Printf("tool call: %s", params.Name)

	// Enforce per-call timeout.
	callCtx, cancel := context.WithTimeout(ctx, ToolCallTimeout)
	defer cancel()

	result := s.executeTool(callCtx, params.Name, params.Arguments)

	// Enforce response size limit.
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Result: ToolResult{
				Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("internal error: %v", err)}},
				IsError: true,
			},
		}
	}
	if len(resultJSON) > MaxResponseBytes {
		return JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Result: ToolResult{
				Content: []ContentBlock{{
					Type: "text",
					Text: fmt.Sprintf("response exceeds maximum size of %d bytes (%d bytes). Use pagination to reduce result size.", MaxResponseBytes, len(resultJSON)),
				}},
				IsError: true,
			},
		}
	}

	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	}
}

// writeResponse serializes a JSON-RPC response and writes it as a single line
// to the writer, followed by a newline.
func writeResponse(w *bufio.Writer, resp JSONRPCResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write response data: %w", err)
	}
	if err := w.WriteByte('\n'); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	return w.Flush()
}

// textResult builds a successful ToolResult with a single JSON text block.
func textResult(data interface{}) ToolResult {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return errorResult(fmt.Sprintf("marshal result: %v", err))
	}
	return ToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: string(jsonBytes),
		}},
	}
}

// errorResult builds an error ToolResult.
func errorResult(msg string) ToolResult {
	return ToolResult{
		Content: []ContentBlock{{
			Type: "text",
			Text: msg,
		}},
		IsError: true,
	}
}
