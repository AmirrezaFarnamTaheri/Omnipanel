package adminruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This check protects the optional live-Postgres ACL test from being silently
// disabled by a truncated or shell-invalid GitHub Actions command.
func TestPostgresACLWorkflowCommandIsShellValid(t *testing.T) {
	path := filepath.Join("..", "..", "..", ".github", "workflows", "enrollment-postgres.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	run := regexp.MustCompile(`(?m)^\s*run: ([^\r\n]+)$`)
	commands := run.FindAllSubmatch(data, -1)
	var matching []string
	for _, match := range commands {
		if strings.Contains(string(match[1]), "TestPostgresAdministratorRoleGrants") {
			matching = append(matching, string(match[1]))
		}
	}
	if len(matching) != 1 {
		t.Fatalf("expected one live ACL test invocation, found %d", len(matching))
	}
	if !strings.Contains(matching[0], "-tags=postgres_integration") ||
		!strings.Contains(matching[0], "-run '^TestPostgresAdministratorRoleGrants$'") {
		t.Fatalf("ACL test selector incomplete or incorrectly quoted: %q", matching[0])
	}
	if runtime.GOOS != "linux" {
		t.Skip("GitHub Actions jobs use Linux bash")
	}
	out, err := exec.Command("bash", "-n", "-c", matching[0]).CombinedOutput()
	if err != nil {
		t.Fatalf("ACL workflow command is invalid bash: %v: %s", err, out)
	}
}
