package attack

import "strings"

// AnalyzeSessionCookie checks common cookie hardening flags.
func AnalyzeSessionCookie(setCookie string) []string {
	flags := []string{}
	lower := strings.ToLower(setCookie)
	if setCookie == "" {
		flags = append(flags, "No session cookie observed")
		return flags
	}
	if !strings.Contains(lower, "httponly") {
		flags = append(flags, "Session cookie missing HttpOnly")
	}
	if !strings.Contains(lower, "secure") {
		flags = append(flags, "Session cookie missing Secure")
	}
	if !strings.Contains(lower, "samesite") {
		flags = append(flags, "Session cookie missing SameSite")
	}
	return flags
}
