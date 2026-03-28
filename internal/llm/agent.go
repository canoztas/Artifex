package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// MaxToolRounds limits how many tool-call round trips the agent can do.
const MaxToolRounds = 15

// ToolExecutor is a function that executes a tool call and returns the result.
type ToolExecutor func(ctx context.Context, name string, args map[string]interface{}) (string, error)

// AgentStep records one step of the agent loop (for UI display).
type AgentStep struct {
	Type      string    `json:"type"` // "thinking", "tool_call", "tool_result", "response"
	Timestamp time.Time `json:"timestamp"`
	Content   string    `json:"content,omitempty"`
	ToolName  string    `json:"tool_name,omitempty"`
	ToolArgs  string    `json:"tool_args,omitempty"`
	ToolResult string   `json:"tool_result,omitempty"`
	IsError   bool      `json:"is_error,omitempty"`
}

// AgentResponse is the full result of an agent chat invocation.
type AgentResponse struct {
	Answer string      `json:"answer"`
	Steps  []AgentStep `json:"steps"`
	Error  string      `json:"error,omitempty"`
}

// RunAgent executes an agentic loop: send messages to the LLM, if it requests
// tool calls execute them, feed results back, repeat until the LLM produces
// a final text response or we hit the round limit.
func RunAgent(
	ctx context.Context,
	provider Provider,
	systemPrompt string,
	userMessage string,
	history []Message,
	tools []ToolDefinition,
	executor ToolExecutor,
) (*AgentResponse, error) {

	result := &AgentResponse{}

	// Build the initial conversation.
	messages := make([]Message, 0, len(history)+2)
	messages = append(messages, Message{Role: RoleSystem, Content: systemPrompt})
	messages = append(messages, history...)
	messages = append(messages, Message{Role: RoleUser, Content: userMessage})

	for round := 0; round < MaxToolRounds; round++ {
		resp, err := provider.Chat(ctx, messages, tools)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}

		// If the model returned text content, record it.
		if resp.Content != "" {
			result.Steps = append(result.Steps, AgentStep{
				Type:      "thinking",
				Timestamp: time.Now(),
				Content:   resp.Content,
			})
		}

		// No tool calls → final answer.
		if len(resp.ToolCalls) == 0 || resp.FinishReason == "stop" {
			result.Answer = resp.Content
			return result, nil
		}

		// The model wants to call tools.
		assistantMsg := Message{
			Role:      RoleAssistant,
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		}
		messages = append(messages, assistantMsg)

		// Execute each tool call.
		for _, tc := range resp.ToolCalls {
			argsJSON, _ := json.Marshal(tc.Arguments)

			result.Steps = append(result.Steps, AgentStep{
				Type:      "tool_call",
				Timestamp: time.Now(),
				ToolName:  tc.Name,
				ToolArgs:  string(argsJSON),
			})

			log.Printf("[agent] calling tool %s(%s)", tc.Name, string(argsJSON))

			toolOutput, toolErr := executor(ctx, tc.Name, tc.Arguments)
			isErr := false
			if toolErr != nil {
				toolOutput = fmt.Sprintf("Error: %v", toolErr)
				isErr = true
			}

			// Truncate very large tool outputs.
			if len(toolOutput) > 50000 {
				toolOutput = toolOutput[:50000] + "\n... [truncated]"
			}

			result.Steps = append(result.Steps, AgentStep{
				Type:       "tool_result",
				Timestamp:  time.Now(),
				ToolName:   tc.Name,
				ToolResult: toolOutput,
				IsError:    isErr,
			})

			messages = append(messages, Message{
				Role:       RoleTool,
				Content:    toolOutput,
				ToolCallID: tc.Name,
			})
		}
	}

	// Hit the round limit.
	result.Answer = "I've reached the maximum number of tool call rounds. Here's what I found so far based on the analysis above."
	if len(result.Steps) > 0 {
		// Try to get a final summary from the model.
		messages = append(messages, Message{
			Role:    RoleUser,
			Content: "Please provide a final summary of your findings based on the tool calls above.",
		})
		resp, err := provider.Chat(ctx, messages, nil) // no tools to force text
		if err == nil && resp.Content != "" {
			result.Answer = resp.Content
		}
	}

	return result, nil
}
