package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/artifex/dfir/internal/models"
	"github.com/google/uuid"
)

const openAIBaseURL = "https://api.openai.com/v1/chat/completions"

// OpenAIProvider implements the Provider interface for OpenAI GPT models.
type OpenAIProvider struct {
	apiKey     string
	model      string
	maxTokens  int
	temp       float64
	timeoutMS  int
	httpClient *http.Client
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

	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	timeout := cfg.TimeoutMS
	if timeout == 0 {
		timeout = 30000
	}

	return &OpenAIProvider{
		apiKey:    cfg.APIKey,
		model:     model,
		maxTokens: maxTokens,
		temp:      cfg.Temperature,
		timeoutMS: timeout,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Millisecond,
		},
	}, nil
}

func (o *OpenAIProvider) Name() string { return "openai" }

func (o *OpenAIProvider) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error) {
	reqBody := o.buildRequest(messages, tools)

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIBaseURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("openai: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai: send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("openai: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai: API error %d: %s", resp.StatusCode, string(body))
	}

	return o.parseResponse(body)
}

type openAIChatRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Tools       []openAITool    `json:"tools,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAITool struct {
	Type     string             `json:"type"`
	Function openAIFunctionDecl `json:"function"`
}

type openAIFunctionDecl struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

type openAIToolCall struct {
	ID       string               `json:"id,omitempty"`
	Type     string               `json:"type"`
	Function openAIToolCallTarget `json:"function"`
}

type openAIToolCallTarget struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openAIChatResponse struct {
	Choices []openAIChoice `json:"choices"`
	Usage   *openAIUsage   `json:"usage,omitempty"`
}

type openAIChoice struct {
	Message      openAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openAIUsage struct {
	TotalTokens int `json:"total_tokens"`
}

func (o *OpenAIProvider) buildRequest(messages []Message, tools []ToolDefinition) openAIChatRequest {
	req := openAIChatRequest{
		Model:       o.model,
		Temperature: o.temp,
		MaxTokens:   o.maxTokens,
	}

	for _, msg := range messages {
		switch msg.Role {
		case RoleSystem:
			req.Messages = append(req.Messages, openAIMessage{
				Role:    "system",
				Content: msg.Content,
			})
		case RoleUser:
			req.Messages = append(req.Messages, openAIMessage{
				Role:    "user",
				Content: msg.Content,
			})
		case RoleAssistant, "assistant":
			assistantMsg := openAIMessage{
				Role:    "assistant",
				Content: msg.Content,
			}
			for _, tc := range msg.ToolCalls {
				argsJSON, _ := json.Marshal(tc.Arguments)
				assistantMsg.ToolCalls = append(assistantMsg.ToolCalls, openAIToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: openAIToolCallTarget{
						Name:      tc.Name,
						Arguments: string(argsJSON),
					},
				})
			}
			req.Messages = append(req.Messages, assistantMsg)
		case RoleTool:
			req.Messages = append(req.Messages, openAIMessage{
				Role:       "tool",
				Content:    msg.Content,
				ToolCallID: msg.ToolCallID,
			})
		}
	}

	if len(tools) > 0 {
		for _, t := range tools {
			req.Tools = append(req.Tools, openAITool{
				Type: "function",
				Function: openAIFunctionDecl{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  t.Parameters,
				},
			})
		}
	}

	return req
}

func (o *OpenAIProvider) parseResponse(body []byte) (*Response, error) {
	var openAIResp openAIChatResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return nil, fmt.Errorf("openai: parse response: %w", err)
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("openai: no choices in response: %s", string(body))
	}

	choice := openAIResp.Choices[0]
	resp := &Response{
		Content:      choice.Message.Content,
		FinishReason: mapOpenAIFinishReason(choice.FinishReason),
	}

	if openAIResp.Usage != nil {
		resp.TokensUsed = openAIResp.Usage.TotalTokens
	}

	for _, tc := range choice.Message.ToolCalls {
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			args = map[string]interface{}{}
		}
		id := tc.ID
		if id == "" {
			id = uuid.New().String()
		}
		resp.ToolCalls = append(resp.ToolCalls, ToolCall{
			ID:        id,
			Name:      tc.Function.Name,
			Arguments: args,
		})
	}

	if len(resp.ToolCalls) > 0 {
		resp.FinishReason = "tool_calls"
	}

	return resp, nil
}

func mapOpenAIFinishReason(reason string) string {
	switch reason {
	case "stop":
		return "stop"
	case "tool_calls":
		return "tool_calls"
	case "length":
		return "length"
	default:
		return "stop"
	}
}
