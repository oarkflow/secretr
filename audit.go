package secretr

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var auditMu sync.Mutex

// LogAudit writes an audit log line with an HMAC signature to prevent tampering.
// NIST SP 800-57: HMAC-SHA256 is used for integrity of audit logs, keyed with the master key.
func LogAudit(operation, key, details string, masterKey []byte) {
	auditMu.Lock()
	defer auditMu.Unlock()
	// Use a daily rotated log file.
	auditPath := filepath.Join(secretrDir, fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02")))
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() {
		_ = f.Close()
	}()
	timestamp := time.Now().Format(time.RFC3339)
	data := fmt.Sprintf("%s|%s|%s|%s", timestamp, operation, key, details)
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(data))
	signature := hex.EncodeToString(mac.Sum(nil))
	line := fmt.Sprintf("%s|%s\n", data, signature)
	_, _ = f.WriteString(line)
}
