package vault

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
func LogAudit(operation, key, details string, masterKey []byte) {
	auditMu.Lock()
	defer auditMu.Unlock()
	auditPath := filepath.Join(vaultDir, "audit.log")
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	timestamp := time.Now().Format(time.RFC3339)
	data := fmt.Sprintf("%s|%s|%s|%s", timestamp, operation, key, details)
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(data))
	signature := hex.EncodeToString(mac.Sum(nil))
	line := fmt.Sprintf("%s|%s\n", data, signature)
	f.WriteString(line)
}
