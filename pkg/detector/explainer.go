package detector

import "fmt"

// Explanation provides detailed info about a finding.
type Explanation struct {
	Description string
	Impact      string
	Remediation string
	References  []string
}

// Explain returns a detailed explanation for a given vulnerability type.
func Explain(finding Finding) Explanation {
	switch finding.Type {
	case "SQL Injection", "Boolean-based Blind SQL Injection", "Time-based Blind SQL Injection":
		return Explanation{
			Description: "SQL Injection occurs when user input is improperly sanitized and concatenated into SQL queries.",
			Impact:      "An attacker can read, modify, or delete database contents, potentially compromising all user data and gaining administrative access.",
			Remediation: "Use parameterized queries (prepared statements) or an ORM that escapes inputs. Never concatenate user input into SQL strings.",
			References:  []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
		}
	case "Reflected XSS (Script Tag)", "Reflected XSS (Double-Quoted Attribute)", "Reflected XSS (Single-Quoted Attribute)", "Reflected XSS (Tag Body)", "Reflected XSS (javascript: URI)", "Reflected XSS (Generic)":
		return Explanation{
			Description: "Cross-Site Scripting (XSS) allows an attacker to inject malicious scripts into web pages viewed by other users.",
			Impact:      "Session hijacking, credential theft, defacement, or redirection to malicious sites.",
			Remediation: "HTML-encode all user-controlled output based on context (HTML body, attribute, JavaScript). Use Content-Security-Policy headers.",
			References:  []string{"https://owasp.org/www-community/attacks/xss/"},
		}
	case "Path Traversal":
		return Explanation{
			Description: "Path Traversal allows an attacker to read arbitrary files from the server filesystem.",
			Impact:      "Disclosure of sensitive files (configs, source code, /etc/passwd) leading to further compromise.",
			Remediation: "Validate file paths with a whitelist. Use `path.Clean()` and ensure the resolved path stays within intended directory.",
			References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
		}
	case "Command Injection":
		return Explanation{
			Description: "Command Injection allows execution of arbitrary system commands on the server.",
			Impact:      "Complete server takeover, data exfiltration, or lateral movement within infrastructure.",
			Remediation: "Avoid calling system commands with user input. If unavoidable, use strict input validation and argument escaping (e.g., exec.Command with args array).",
			References:  []string{"https://owasp.org/www-community/attacks/Command_Injection"},
		}
	case "JNDI Injection (Log4Shell)":
		return Explanation{
			Description: "Log4Shell is a critical vulnerability in Log4j2 that allows remote code execution via JNDI lookups.",
			Impact:      "Full remote code execution on the server, often without authentication.",
			Remediation: "Upgrade Log4j to 2.17.0+ or set `log4j2.formatMsgNoLookups=true`.",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		}
	case "Error-based Information Disclosure":
		return Explanation{
			Description: "Detailed error messages reveal internal implementation details (database type, file paths, stack traces).",
			Impact:      "Helps attackers fingerprint technologies and craft more targeted attacks.",
			Remediation: "Configure custom error pages in production. Never display raw exceptions to users.",
			References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"},
		}
	case "Path Disclosure":
		return Explanation{
			Description: "Full server file paths are exposed in error messages or responses.",
			Impact:      "Reveals server directory structure, aiding in path traversal and local file inclusion attacks.",
			Remediation: "Suppress file paths in error messages. Use generic error pages.",
			References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"},
		}
	default:
		return Explanation{
			Description: "Potential security weakness detected.",
			Impact:      "Further investigation required.",
			Remediation: "Review the evidence and apply security best practices.",
			References:  []string{},
		}
	}
}

// FormatExplanation returns a nicely formatted string for CLI output.
func FormatExplanation(f Finding) string {
	exp := Explain(f)
	return fmt.Sprintf(`
🔍 VULNERABILITY: %s
──────────────────────────────────────────
📖 Description: %s
💥 Impact:      %s
🛡️ Remediation: %s
🔗 Reference:   %s
`,
		f.Type,
		exp.Description,
		exp.Impact,
		exp.Remediation,
		exp.References[0])
}
