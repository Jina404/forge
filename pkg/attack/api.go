package attack

import "net/http"

// CheckRateLimitHeaders identifies obvious missing API rate-limit controls.
func CheckRateLimitHeaders(headers http.Header) (bool, string) {
	if headers.Get("X-RateLimit-Limit") == "" && headers.Get("RateLimit-Limit") == "" {
		return true, "Rate-limit headers are not present"
	}
	return false, ""
}
