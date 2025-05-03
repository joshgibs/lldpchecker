package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

// fakeRunner allows simulating SSHRunner behavior for tests
type fakeRunner struct {
	cmdOutput map[string]string
	cmdErr    map[string]error
	files     map[string]string // remotePath -> content
}

func (f *fakeRunner) RunCommand(ctx context.Context, host, cmd string) (string, error) {
	key := host + ":" + cmd
	return f.cmdOutput[key], f.cmdErr[key]
}

func (f *fakeRunner) FetchFile(ctx context.Context, host, remotePath, localPath string) error {
	content, ok := f.files[remotePath]
	if !ok {
		return os.ErrNotExist
	}
	return os.WriteFile(localPath, []byte(content), 0644)
}

func (f *fakeRunner) CleanupRemote(ctx context.Context, host, remotePath string) {
	// no-op
}

func TestParseCSV(t *testing.T) {
	tmp := t.TempDir()
	csvPath := filepath.Join(tmp, "test.csv")
	content := `hostname,local_iface,expected_switch,expected_port
h1,eth0,s1,p1
h2,eth1,s2,p2
`
	if err := os.WriteFile(csvPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write CSV: %v", err)
	}
	refs, err := parseCSV(csvPath)
	if err != nil {
		t.Fatalf("parseCSV error: %v", err)
	}
	exp := map[string]map[string]ReferenceEntry{
		"h1": {"eth0": {"h1", "eth0", "s1", "p1"}},
		"h2": {"eth1": {"h2", "eth1", "s2", "p2"}},
	}
	if !reflect.DeepEqual(refs, exp) {
		t.Errorf("unexpected refs: got %v, want %v", refs, exp)
	}
}

func TestReadHosts(t *testing.T) {
	txt := "# comment\nh1\nh2\n\nh3"
	tmp := t.TempDir()
	hostsPath := filepath.Join(tmp, "hosts.txt")
	if err := os.WriteFile(hostsPath, []byte(txt), 0644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}
	hosts, err := readHosts(hostsPath)
	if err != nil {
		t.Fatalf("readHosts error: %v", err)
	}
	exp := []string{"h1", "h2", "h3"}
	if !reflect.DeepEqual(hosts, exp) {
		t.Errorf("unexpected hosts: got %v, want %v", hosts, exp)
	}
}

func TestCheckJSON(t *testing.T) {
	// prepare a sample LLDP JSON file
	jsonContent := `{
	  "lldp": {
	    "interface": [
	      {"ifname": "eth0", "port": {"id": {"value": "Gi1"}}, "chassis": {"name": "sw1"}},
	      {"ifname": "eth1", "port": {"id": {"value": "Gi2"}}, "chassis": {"name": "sw2"}}
	    ]
	  }
	}`
	tmp := t.TempDir()
	jsonPath := filepath.Join(tmp, "h1-lldp.json")
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("write JSON: %v", err)
	}

	refs := map[string]map[string]ReferenceEntry{
		"h1": {
			"eth0": {"h1", "eth0", "sw1", "Gi1"},
			"eth1": {"h1", "eth1", "sw2", "Gi2"},
		},
	}

	// success case
	if err := checkJSON(jsonPath, "h1", refs); err != nil {
		t.Errorf("checkJSON error: %v", err)
	}

	// missing interface
	refsBad := map[string]map[string]ReferenceEntry{"h1": {"eth0": {"h1", "eth0", "sw1", "Gi1"}}}
	if err := checkJSON(jsonPath, "h1", refsBad); err == nil {
		t.Errorf("expected error on missing interface, got nil")
	}
}

func TestInitConfigOverride(t *testing.T) {
	// write a YAML config
	yaml := `hosts-file: "a.txt"
csv-file: "b.csv"
json-dir: "out"
concurrency: 5
timeout: "10s"
retries: 1
ssh-user: "user1"
key-file: "key"
ssh-password: "pw"
remote-dir: "/tmp"
`
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "conf.yaml")
	os.WriteFile(cfgPath, []byte(yaml), 0644)

	// simulate flags: only override csv-file
	root := &cobra.Command{PreRunE: initConfig, RunE: runCheck}
	flags := root.PersistentFlags()
	flags.StringVar(&cfg.ConfigFile, "config-file", cfgPath, "cfg")
	flags.StringVar(&cfg.CSVFile, "csv", "override.csv", "csv")
	// other flags left default
	root.ParseFlags([]string{"--config-file", cfgPath, "--csv", "override.csv"})
	if err := initConfig(root, []string{}); err != nil {
		t.Fatalf("initConfig error: %v", err)
	}
	// csv should be overridden
	if cfg.CSVFile != "override.csv" {
		t.Errorf("expected CSVFile override, got %s", cfg.CSVFile)
	}
	// hosts-file should come from YAML
	if cfg.HostsFile != "a.txt" {
		t.Errorf("expected hosts-file from YAML, got %s", cfg.HostsFile)
	}
}

func TestSSHRunnerNoAuth(t *testing.T) {
	if _, err := NewSSHRunner("", "", ""); err == nil {
		t.Error("expected error when no auth methods provided")
	}
}

// Additional tests could stub time.Sleep via an interface or monkey-patch, and test RunCommand backoff logic

// End of tests
