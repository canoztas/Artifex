package audit

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/pickaxe/dfir/internal/models"
)

// AuditStore defines the interface the audit logger requires for persistence.
type AuditStore interface {
	AppendAuditEntry(entry models.AuditEntry) (int64, error)
	GetAuditLog(caseID string, limit, offset int) ([]models.AuditEntry, error)
}

// Logger provides audit logging with hash-chain integrity verification.
type Logger struct {
	store AuditStore
}

// NewLogger creates a new audit Logger backed by the given store.
func NewLogger(store AuditStore) *Logger {
	return &Logger{store: store}
}

// Log records an action in the audit log for the specified case.
// The hash chain is maintained by the underlying store's AppendAuditEntry,
// but this method builds the entry with the proper timestamp and fields.
func (l *Logger) Log(caseID, actor, action, tool, details string) error {
	entry := models.AuditEntry{
		CaseID:    caseID,
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Tool:      tool,
		Details:   details,
	}

	_, err := l.store.AppendAuditEntry(entry)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}

// GetLog retrieves audit log entries for a case with pagination.
func (l *Logger) GetLog(caseID string, limit, offset int) ([]models.AuditEntry, error) {
	entries, err := l.store.GetAuditLog(caseID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("get audit log: %w", err)
	}
	return entries, nil
}

// ComputeEntryHash computes the SHA-256 hash for an audit entry given the
// previous entry's hash. The hash input is the concatenation of:
// prev_hash + timestamp + actor + action + details.
func ComputeEntryHash(prevHash string, timestamp time.Time, actor, action, details string) string {
	hashInput := strings.Join([]string{
		prevHash,
		timestamp.Format(time.RFC3339Nano),
		actor,
		action,
		details,
	}, "")
	h := sha256.Sum256([]byte(hashInput))
	return fmt.Sprintf("%x", h)
}

// VerifyChain validates the hash chain integrity of a sequence of audit entries.
// It returns the index of the first invalid entry, or -1 if the chain is valid.
func VerifyChain(entries []models.AuditEntry) int {
	for i, entry := range entries {
		expected := ComputeEntryHash(
			entry.PrevHash,
			entry.Timestamp,
			entry.Actor,
			entry.Action,
			entry.Details,
		)
		if entry.EntryHash != expected {
			return i
		}

		// Verify prev_hash linkage (skip the first entry).
		if i > 0 && entry.PrevHash != entries[i-1].EntryHash {
			return i
		}
	}
	return -1
}
