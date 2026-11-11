package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

// AuditEntry is one mutation attempt. The log is append-only JSON lines so a
// remote change can always be traced back to a request and a config digest.
type AuditEntry struct {
	Time         string `json:"time"`
	RequestID    string `json:"request_id,omitempty"`
	Kind         string `json:"kind"`
	TargetNodeID string `json:"target_node_id,omitempty"`
	SourceNodeID string `json:"source_node_id,omitempty"`
	RouteID      string `json:"route_id,omitempty"`
	Domain       string `json:"domain,omitempty"`
	IfMatch      string `json:"if_match,omitempty"`
	HashBefore   string `json:"hash_before,omitempty"`
	HashAfter    string `json:"hash_after,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

// AuditLog writes audit entries to <base_dir>/control-audit.jsonl.
type AuditLog struct {
	path string
	mu   sync.Mutex
}

func NewAuditLog(baseDir string) *AuditLog {
	if baseDir == "" {
		return nil
	}
	return &AuditLog{path: filepath.Join(baseDir, auditFileName)}
}

// Append never blocks a request on disk failure: a lost audit line is reported
// but the mutation result is still returned.
func (a *AuditLog) Append(entry AuditEntry) {
	if a == nil {
		return
	}
	entry.Time = time.Now().UTC().Format(time.RFC3339)
	line, err := json.Marshal(entry)
	if err != nil {
		log.Error("Failed to encode audit entry", "err", err)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Error("Failed to open audit log", "path", a.path, "err", err)
		return
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		log.Error("Failed to write audit entry", "err", err)
	}
}
