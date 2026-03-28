package llm

import (
	"context"
	"fmt"

	"github.com/pickaxe/dfir/internal/models"
)

// Role constants for chat messages.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "model"
	RoleTool      = "tool"
)

// Message represents a single message in a conversation.
type Message struct {
	Role       string      `json:"role"`
	Content    string      `json:"content"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
}

// ToolCall represents an LLM request to invoke a tool.
type ToolCall struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolResult represents the result of executing a tool call.
type ToolResult struct {
	CallID  string `json:"call_id"`
	Content string `json:"content"`
	IsError bool   `json:"is_error"`
}

// ToolDefinition describes a tool the LLM can call.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// Response is the LLM's reply.
type Response struct {
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// FinishReason: "stop", "tool_calls", "length", "error"
	FinishReason string `json:"finish_reason"`
	TokensUsed   int    `json:"tokens_used,omitempty"`
}

// Provider is the interface all LLM backends must implement.
type Provider interface {
	// Chat sends messages to the LLM and returns a response.
	// tools defines available function calls the model can make.
	Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error)

	// Name returns the provider identifier.
	Name() string
}

// NewProvider creates an LLM provider from the application config.
func NewProvider(cfg models.LLMConfig) (Provider, error) {
	switch cfg.Provider {
	case "gemini":
		return NewGeminiProvider(cfg)
	case "anthropic":
		return NewAnthropicProvider(cfg)
	case "openai":
		return NewOpenAIProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %q (supported: gemini, anthropic, openai)", cfg.Provider)
	}
}
