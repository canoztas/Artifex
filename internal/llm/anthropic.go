package llm

import (
	"context"
	"fmt"

	"github.com/pickaxe/dfir/internal/models"
)

// AnthropicProvider implements the Provider interface for Anthropic Claude.
// This is a placeholder for future implementation.
type AnthropicProvider struct {
	apiKey string
	model  string
}

// NewAnthropicProvider creates an Anthropic provider.
func NewAnthropicProvider(cfg models.LLMConfig) (*AnthropicProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anthropic: api_key is required")
	}
	model := cfg.Model
	if model == "" || model == "auto" {
		model = "claude-sonnet-4-20250514"
	}
	return &AnthropicProvider{apiKey: cfg.APIKey, model: model}, nil
}

func (a *AnthropicProvider) Name() string { return "anthropic" }

func (a *AnthropicProvider) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error) {
	return nil, fmt.Errorf("anthropic provider not yet implemented — set provider to 'gemini' in config.json")
}
