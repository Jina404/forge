package attack

import "strings"

// DetectReflectedXSS reports whether payload reflection indicates XSS risk.
func DetectReflectedXSS(responseBody string, payload string) (bool, string) {
	if payload == "" || responseBody == "" {
		return false, ""
	}
	if strings.Contains(responseBody, "<script>"+payload+"</script>") {
		return true, "script_tag"
	}
	if strings.Contains(responseBody, payload) {
		return true, "generic_reflection"
	}
	return false, ""
}
