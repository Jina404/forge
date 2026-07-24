package attack

import "strings"

// JWTIssue models token weaknesses discovered during analysis.
type JWTIssue struct {
	Title   string
	Details string
}

// AnalyzeJWTHeader checks obvious JWT anti-patterns from decoded header JSON text.
func AnalyzeJWTHeader(decodedHeader string) []JWTIssue {
	issues := []JWTIssue{}
	lower := strings.ToLower(decodedHeader)
	if strings.Contains(lower, `"alg":"none"`) {
		issues = append(issues, JWTIssue{Title: "JWT none algorithm", Details: "Token allows unsigned algorithm."})
	}
	if strings.Contains(lower, `"jku"`) {
		issues = append(issues, JWTIssue{Title: "JWT remote key reference", Details: "Header includes jku; validate strict allowlist."})
	}
	return issues
}
