package secretr

// CheckAccess is now enhanced with policy rules.
func CheckAccess(user, resource, action string) bool {
	return CheckPolicy(user, resource, action)
}

type Policy struct {
	Users     []string
	Actions   []string
	Resources []string
}

// NEW: Global policies defining access.
// Admin can perform any action on any resource.
// Default policy: All other users can only read non‑sensitive resources.
var policies = []Policy{
	{Users: []string{"admin"}, Actions: []string{"*"}, Resources: []string{"*"}},
	{Users: []string{"*"}, Actions: []string{"read"}, Resources: []string{"non_sensitive"}},
}

// CheckPolicy to use granular policies.
// CheckPolicy performs a basic ACL check.
// For example, the admin user is allowed all actions.
// Non‑admin users are only allowed read access on non‑sensitive resources.
func CheckPolicy(user, resource, action string) bool {
	for _, p := range policies {
		userAllowed := false
		for _, u := range p.Users {
			if u == "*" || u == user {
				userAllowed = true
				break
			}
		}
		if !userAllowed {
			continue
		}
		actionAllowed := false
		for _, a := range p.Actions {
			if a == "*" || a == action {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			continue
		}
		for _, r := range p.Resources {
			if r == "*" || r == resource {
				return true
			}
		}
	}
	return false
}
