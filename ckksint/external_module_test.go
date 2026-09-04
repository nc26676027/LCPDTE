package ckksint_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExternalModuleImportsCKKSIntWithoutVendor(t *testing.T) {
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot := filepath.Dir(packageDir)
	temporaryModule := t.TempDir()

	goMod := fmt.Sprintf(`module example.com/ckksintconsumer

go 1.23.11

require github.com/nc26676027/LCPDTE v0.0.0

replace github.com/nc26676027/LCPDTE => %q
`, filepath.ToSlash(repositoryRoot))
	if err := os.WriteFile(filepath.Join(temporaryModule, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}

	consumer := `package consumer

import "github.com/nc26676027/LCPDTE/ckksint"

var _ func() (*ckksint.RouteBDepth2Client, *ckksint.RouteBDepth2Server, ckksint.RouteBDepth2SetupInfo, error) = ckksint.NewCanonicalRouteBDepth2
`
	if err := os.WriteFile(filepath.Join(temporaryModule, "consumer.go"), []byte(consumer), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("go", "test", "-count=1", ".")
	command.Dir = temporaryModule
	command.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("external module failed to import ckksint: %v\n%s", err, output)
	}
}
