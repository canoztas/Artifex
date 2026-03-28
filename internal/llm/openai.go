package llm

import (
	"context"
	"fmt"

	"github.com/pickaxe/dfir/internal/models"
)

// OpenAIProvider implements the Provider interface for OpenAI GPT.
// This is a placeholder for future implementation.
type OpenAIProvider struct {
	apiKey string
	model  string
}

// NewOpenAIProvider creates an OpenAI provider.
func NewOpenAIProvider(cfg models.LLMConfig) (*OpenAIProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("openai: api_key is required")
	}
	model := cfg.Model
	if model == "" || model == "auto" {
		model = "gpt-4o"
	}
	return &OpenAIProvider{apiKey: cfg.APIKey, model: model}, nil
}

func (o *OpenAIProvider) Name() string { return "openai" }

func (o *OpenAIProvider) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error) {
	return nil, fmt.Errorf("openai provider not yet implemented — set provider to 'gemini' in config.json")
}
