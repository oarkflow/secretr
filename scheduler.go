package secretr

import (
	"log"
	"time"
)

// leaseRevocation starts a background task to revoke expired dynamic secrets.
func (v *Secretr) leaseRevocation(interval time.Duration) {
	go func() {
		for {
			time.Sleep(interval)
			v.mu.Lock()
			now := time.Now()
			for key, versions := range v.store.KVSecrets {
				var newVersions []SecretMeta
				revoked := false
				for _, meta := range versions {
					if meta.LeaseUntil.Before(now) {
						revoked = true
						LogAudit("lease_revoked", key, "dynamic secret expired and revoked", v.masterKey)
					} else {
						newVersions = append(newVersions, meta)
					}
				}
				if revoked {
					v.store.KVSecrets[key] = newVersions
					// Optionally remove static secret if no valid versions remain.
					if len(newVersions) == 0 {
						delete(v.store.KVSecrets, key)
						delete(v.store.Data, key)
					}
					_ = v.Save()
					log.Printf("Revoked expired dynamic secret(s) for key: %s", key)
				}
			}
			v.mu.Unlock()
		}
	}()
}
