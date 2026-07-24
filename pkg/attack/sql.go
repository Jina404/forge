package attack

import "strings"

// IsPotentialSQLiPayload performs quick payload classification.
func IsPotentialSQLiPayload(payload string) bool {
	lower := strings.ToLower(payload)
	patterns := []string{"' or '1'='1", "union select", "sleep(", "waitfor delay", "information_schema"}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
