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

const deepSeekBaseURL = "https://api.deepseek.com/chat/completions"

// DeepSeekProvider implements the Provider interface for DeepSeek chat models.
type DeepSeekProvider struct {
	apiKey     string
	model      string
	maxTokens  int
	temp       float64
	timeoutMS  int
	httpClient *http.Client
}

// NewDeepSeekProvider creates a DeepSeek provider.
func NewDeepSeekProvider(cfg models.LLMConfig) (*DeepSeekProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("deepseek: api_key is required")
	}

	model := cfg.Model
	if model == "" || model == "auto" {
		model = "deepseek-chat"
	}

	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	timeout := cfg.TimeoutMS
	if timeout == 0 {
		timeout = 30000
	}

	return &DeepSeekProvider{
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

func (d *DeepSeekProvider) Name() string { return "deepseek" }

func (d *DeepSeekProvider) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error) {
	reqBody := d.buildRequest(messages, tools)

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("deepseek: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deepSeekBaseURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("deepseek: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.apiKey)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("deepseek: send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("deepseek: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deepseek: API error %d: %s", resp.StatusCode, string(body))
	}

	return d.parseResponse(body)
}

type deepSeekChatRequest struct {
	Model       string               `json:"model"`
	Messages    []deepSeekMessage    `json:"messages"`
	Tools       []deepSeekTool       `json:"tools,omitempty"`
	Temperature float64              `json:"temperature,omitempty"`
	MaxTokens   int                  `json:"max_tokens,omitempty"`
}

type deepSeekMessage struct {
	Role       string                 `json:"role"`
	Content    string                 `json:"content,omitempty"`
	ToolCalls  []deepSeekToolCall     `json:"tool_calls,omitempty"`
	ToolCallID string                 `json:"tool_call_id,omitempty"`
}

type deepSeekTool struct {
	Type     string                   `json:"type"`
	Function deepSeekFunctionDecl     `json:"function"`
}

type deepSeekFunctionDecl struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

type deepSeekToolCall struct {
	ID       string                   `json:"id,omitempty"`
	Type     string                   `json:"type"`
	Function deepSeekToolCallTarget   `json:"function"`
}

type deepSeekToolCallTarget struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type deepSeekChatResponse struct {
	Choices []deepSeekChoice `json:"choices"`
	Usage   *deepSeekUsage   `json:"usage,omitempty"`
}

type deepSeekChoice struct {
	Message      deepSeekMessage `json:"message"`
	FinishReason string          `json:"finish_reason"`
}

type deepSeekUsage struct {
	TotalTokens int `json:"total_tokens"`
}

func (d *DeepSeekProvider) buildRequest(messages []Message, tools []ToolDefinition) deepSeekChatRequest {
	req := deepSeekChatRequest{
		Model:       d.model,
		Temperature: d.temp,
		MaxTokens:   d.maxTokens,
	}

	for _, msg := range messages {
		switch msg.Role {
		case RoleSystem:
			req.Messages = append(req.Messages, deepSeekMessage{
				Role:    "system",
				Content: msg.Content,
			})
		case RoleUser:
			req.Messages = append(req.Messages, deepSeekMessage{
				Role:    "user",
				Content: msg.Content,
			})
		case RoleAssistant, "assistant":
			assistantMsg := deepSeekMessage{
				Role:    "assistant",
				Content: msg.Content,
			}
			for _, tc := range msg.ToolCalls {
				argsJSON, _ := json.Marshal(tc.Arguments)
				assistantMsg.ToolCalls = append(assistantMsg.ToolCalls, deepSeekToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: deepSeekToolCallTarget{
						Name:      tc.Name,
						Arguments: string(argsJSON),
					},
				})
			}
			req.Messages = append(req.Messages, assistantMsg)
		case RoleTool:
			req.Messages = append(req.Messages, deepSeekMessage{
				Role:       "tool",
				Content:    msg.Content,
				ToolCallID: msg.ToolCallID,
			})
		}
	}

	if len(tools) > 0 {
		for _, t := range tools {
			req.Tools = append(req.Tools, deepSeekTool{
				Type: "function",
				Function: deepSeekFunctionDecl{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  t.Parameters,
				},
			})
		}
	}

	return req
}

func (d *DeepSeekProvider) parseResponse(body []byte) (*Response, error) {
	var deepSeekResp deepSeekChatResponse
	if err := json.Unmarshal(body, &deepSeekResp); err != nil {
		return nil, fmt.Errorf("deepseek: parse response: %w", err)
	}

	if len(deepSeekResp.Choices) == 0 {
		return nil, fmt.Errorf("deepseek: no choices in response: %s", string(body))
	}

	choice := deepSeekResp.Choices[0]
	resp := &Response{
		Content:      choice.Message.Content,
		FinishReason: mapDeepSeekFinishReason(choice.FinishReason),
	}

	if deepSeekResp.Usage != nil {
		resp.TokensUsed = deepSeekResp.Usage.TotalTokens
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

func mapDeepSeekFinishReason(reason string) string {
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
