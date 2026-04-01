package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/artifex/dfir/internal/models"
	"github.com/google/uuid"
)

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta"

// GeminiProvider implements the Provider interface using Google's Gemini API.
type GeminiProvider struct {
	apiKey     string
	model      string
	maxTokens  int
	temp       float64
	timeoutMS  int
	httpClient *http.Client
}

// NewGeminiProvider creates a Gemini provider from config.
func NewGeminiProvider(cfg models.LLMConfig) (*GeminiProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("gemini: api_key is required")
	}

	model := cfg.Model
	if model == "" || model == "auto" {
		model = "gemini-2.5-flash"
	}

	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	timeout := cfg.TimeoutMS
	if timeout == 0 {
		timeout = 30000
	}

	return &GeminiProvider{
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

func (g *GeminiProvider) Name() string { return "gemini" }

// Chat sends a conversation to Gemini and returns the response.
func (g *GeminiProvider) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error) {
	reqBody := g.buildRequest(messages, tools)

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", geminiBaseURL, g.model, g.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("gemini: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini: send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("gemini: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini: API error %d: %s", resp.StatusCode, string(body))
	}

	return g.parseResponse(body)
}

// ---------------------------------------------------------------------------
// Gemini API request/response types
// ---------------------------------------------------------------------------

type geminiRequest struct {
	Contents          []geminiContent         `json:"contents"`
	Tools             []geminiTool            `json:"tools,omitempty"`
	SystemInstruction *geminiContent          `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string                  `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResponse `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}

type geminiFunctionResponse struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response"`
}

type geminiTool struct {
	FunctionDeclarations []geminiFunctionDecl `json:"functionDeclarations"`
}

type geminiFunctionDecl struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

type geminiGenerationConfig struct {
	Temperature     float64 `json:"temperature,omitempty"`
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
}

type geminiResponse struct {
	Candidates    []geminiCandidate    `json:"candidates"`
	UsageMetadata *geminiUsageMetadata `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason"`
}

type geminiUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

func (g *GeminiProvider) buildRequest(messages []Message, tools []ToolDefinition) geminiRequest {
	req := geminiRequest{
		GenerationConfig: &geminiGenerationConfig{
			Temperature:     g.temp,
			MaxOutputTokens: g.maxTokens,
		},
	}

	// Extract system instruction from messages.
	var contents []geminiContent
	for _, msg := range messages {
		switch msg.Role {
		case RoleSystem:
			req.SystemInstruction = &geminiContent{
				Parts: []geminiPart{{Text: msg.Content}},
			}

		case RoleUser:
			contents = append(contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: msg.Content}},
			})

		case RoleAssistant, "assistant":
			var parts []geminiPart
			if msg.Content != "" {
				parts = append(parts, geminiPart{Text: msg.Content})
			}
			for _, tc := range msg.ToolCalls {
				parts = append(parts, geminiPart{
					FunctionCall: &geminiFunctionCall{
						Name: tc.Name,
						Args: tc.Arguments,
					},
				})
			}
			contents = append(contents, geminiContent{
				Role:  "model",
				Parts: parts,
			})

		case RoleTool:
			// Tool results go back as user messages with functionResponse parts.
			var respData map[string]interface{}
			if err := json.Unmarshal([]byte(msg.Content), &respData); err != nil {
				respData = map[string]interface{}{"result": msg.Content}
			}
			toolName := msg.ToolName
			if toolName == "" {
				toolName = msg.ToolCallID
			}
			contents = append(contents, geminiContent{
				Role: "user",
				Parts: []geminiPart{{
					FunctionResponse: &geminiFunctionResponse{
						Name:     toolName,
						Response: respData,
					},
				}},
			})
		}
	}
	req.Contents = contents

	// Convert tool definitions to Gemini format.
	if len(tools) > 0 {
		var decls []geminiFunctionDecl
		for _, t := range tools {
			decls = append(decls, geminiFunctionDecl{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			})
		}
		req.Tools = []geminiTool{{FunctionDeclarations: decls}}
	}

	return req
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

func (g *GeminiProvider) parseResponse(body []byte) (*Response, error) {
	var gemResp geminiResponse
	if err := json.Unmarshal(body, &gemResp); err != nil {
		return nil, fmt.Errorf("gemini: parse response: %w", err)
	}

	if len(gemResp.Candidates) == 0 {
		return nil, fmt.Errorf("gemini: no candidates in response: %s", string(body))
	}

	candidate := gemResp.Candidates[0]
	resp := &Response{
		FinishReason: mapFinishReason(candidate.FinishReason),
	}

	if gemResp.UsageMetadata != nil {
		resp.TokensUsed = gemResp.UsageMetadata.TotalTokenCount
	}

	var textParts []string
	for _, part := range candidate.Content.Parts {
		if part.Text != "" {
			textParts = append(textParts, part.Text)
		}
		if part.FunctionCall != nil {
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{
				ID:        uuid.New().String(),
				Name:      part.FunctionCall.Name,
				Arguments: part.FunctionCall.Args,
			})
		}
	}
	resp.Content = strings.Join(textParts, "")

	if len(resp.ToolCalls) > 0 {
		resp.FinishReason = "tool_calls"
	}

	return resp, nil
}

func mapFinishReason(reason string) string {
	switch reason {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY":
		return "safety"
	case "RECITATION":
		return "recitation"
	default:
		return "stop"
	}
}
