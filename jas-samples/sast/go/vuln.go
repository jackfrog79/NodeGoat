// JAS SAST demo fixture (Go). Not part of any Go module in this repo.
//
// Findings demonstrated:
//   - CWE-78 / OWASP A03:2021 Injection: OS command injection via a shell
//     invocation built from user input (High).
//   - CWE-918 SSRF: outbound request to a user-controlled URL with no
//     allowlist (Medium).
//   - CWE-327 Use of a broken/weak crypto algorithm: MD5 used to "hash" a
//     password (Medium).
package jassamples

import (
	"crypto/md5"
	"net/http"
	"os/exec"
)

// Vulnerable: userInput flows unsanitized into a shell command.
func ConvertFile(userInput string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", "convert "+userInput+" output.png")
	return cmd.CombinedOutput()
}

// Vulnerable: server-side request forgery — no validation of the target host.
func FetchRemoteResource(userSuppliedURL string) (*http.Response, error) {
	return http.Get(userSuppliedURL)
}

// Vulnerable: MD5 is not suitable for password storage.
func WeakHashPassword(password string) [16]byte {
	return md5.Sum([]byte(password))
}
