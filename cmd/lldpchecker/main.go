// LLDPCHECKER: A robust, concurrent LLDP cable verification tool
// Features: Go SSH/SFTP client, retries with backoff, graceful shutdown,
// CSV header parsing, optional password authentication, YAML config support, and configurable concurrency/timeouts.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// Config holds all CLI and YAML-configurable settings.
type Config struct {
	ConfigFile  string        `yaml:"config-file"`
	HostsFile   string        `yaml:"hosts-file"`
	CSVFile     string        `yaml:"csv-file"`
	OutDir      string        `yaml:"json-dir"`
	SSHUser     string        `yaml:"ssh-user"`
	KeyFile     string        `yaml:"key-file"`
	SSHPassword string        `yaml:"ssh-password"`
	RemoteDir   string        `yaml:"remote-dir"`
	Concurrency int           `yaml:"concurrency"`
	Timeout     time.Duration `yaml:"timeout"`
	Retries     int           `yaml:"retries"`
}

var (
	cfg    Config
	logger *slog.Logger
)

// ReferenceEntry holds the expected LLDP mapping.
type ReferenceEntry struct {
	Hostname, Interface, ExpSwitch, ExpPort string
}

// LLDPJSON matches the structure emitted by `lldpcli show neighbor -f JSON`.
type LLDPJSON struct {
	LLDP struct {
		Interface []struct {
			IfName string `json:"ifname"`
			Port   struct {
				ID struct {
					Value string `json:"value"`
				} `json:"id"`
			} `json:"port"`
			Chassis struct {
				Name string `json:"name"`
			} `json:"chassis"`
		} `json:"interface"`
	} `json:"lldp"`
}

// Runner defines methods to run commands and transfer files.
type Runner interface {
	RunCommand(ctx context.Context, host, cmd string) (string, error)
	FetchFile(ctx context.Context, host, remotePath, localPath string) error
	CleanupRemote(ctx context.Context, host, remotePath string)
}

// SSHRunner implements Runner with native SSH and SFTP.
type SSHRunner struct{ config *ssh.ClientConfig }

// NewSSHRunner returns an SSHRunner using public-key and/or password auth.
func NewSSHRunner(user, keyFile, password string) (*SSHRunner, error) {
	auths := []ssh.AuthMethod{}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err == nil {
			signer, err2 := ssh.ParsePrivateKey(data)
			if err2 == nil {
				auths = append(auths, ssh.PublicKeys(signer))
			}
		}
	}
	if password != "" {
		auths = append(auths, ssh.Password(password))
	}
	if len(auths) == 0 {
		return nil, errors.New("no SSH auth methods: provide key-file or ssh-password")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return &SSHRunner{config: cfg}, nil
}

// dial creates an SSH client connection.
func (r *SSHRunner) dial(host string) (*ssh.Client, error) {
	return ssh.Dial("tcp", net.JoinHostPort(host, "22"), r.config)
}

// RunCommand executes a remote command with retries & exponential backoff.
func (r *SSHRunner) RunCommand(ctx context.Context, host, cmd string) (string, error) {
	var out string
	for i := 0; i <= cfg.Retries; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		client, err := r.dial(host)
		if err != nil {
			logger.Warn("dial failed", "host", host, "attempt", i, "err", err)
			time.Sleep(time.Second * time.Duration(1<<i))
			continue
		}
		sess, err := client.NewSession()
		if err != nil {
			client.Close()
			logger.Warn("session failed", "host", host, "err", err)
			time.Sleep(time.Second * time.Duration(1<<i))
			continue
		}
		b, err := sess.CombinedOutput(cmd)
		sess.Close()
		client.Close()
		if err == nil {
			out = string(b)
			break
		}
		logger.Warn("command retry", "host", host, "attempt", i, "err", err)
		time.Sleep(time.Second * time.Duration(1<<i))
	}
	if out == "" {
		return "", fmt.Errorf("command failed after %d retries", cfg.Retries)
	}
	return out, nil
}

// FetchFile pulls a file via SFTP and writes locally.
func (r *SSHRunner) FetchFile(ctx context.Context, host, remotePath, localPath string) error {
	client, err := r.dial(host)
	if err != nil {
		return err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return err
	}
	defer sftpClient.Close()
	in, err := sftpClient.Open(remotePath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// CleanupRemote removes the temporary remote file.
func (r *SSHRunner) CleanupRemote(ctx context.Context, host, remotePath string) {
	_, _ = r.RunCommand(ctx, host, fmt.Sprintf("rm -f %s", remotePath))
}

// parseCSV loads expected mappings from CSV using header names.
func parseCSV(path string) (map[string]map[string]ReferenceEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	headers, err := r.Read()
	if err != nil {
		return nil, err
	}
	idx := make(map[string]int)
	for i, h := range headers {
		idx[strings.ToLower(h)] = i
	}
	refs := make(map[string]map[string]ReferenceEntry)
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		h, iFace := rec[idx["hostname"]], rec[idx["local_iface"]]
		sw, port := rec[idx["expected_switch"]], rec[idx["expected_port"]]
		if refs[h] == nil {
			refs[h] = make(map[string]ReferenceEntry)
		}
		refs[h][iFace] = ReferenceEntry{h, iFace, sw, port}
	}
	return refs, nil
}

// readHosts returns hosts, skipping blank or commented lines.
func readHosts(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	hosts := []string{}
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		hosts = append(hosts, l)
	}
	return hosts, s.Err()
}

// initConfig loads YAML config and applies defaults, flags override.
func initConfig(cmd *cobra.Command, args []string) error {
	if cfg.ConfigFile == "" {
		return nil
	}
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		return err
	}
	var fileCfg Config
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return err
	}
	flags := cmd.Flags()
	if !flags.Changed("hosts-file") && fileCfg.HostsFile != "" {
		cfg.HostsFile = fileCfg.HostsFile
	}
	if !flags.Changed("csv") && fileCfg.CSVFile != "" {
		cfg.CSVFile = fileCfg.CSVFile
	}
	if !flags.Changed("json-dir") && fileCfg.OutDir != "" {
		cfg.OutDir = fileCfg.OutDir
	}
	if !flags.Changed("ssh-user") && fileCfg.SSHUser != "" {
		cfg.SSHUser = fileCfg.SSHUser
	}
	if !flags.Changed("key-file") && fileCfg.KeyFile != "" {
		cfg.KeyFile = fileCfg.KeyFile
	}
	if !flags.Changed("ssh-password") && fileCfg.SSHPassword != "" {
		cfg.SSHPassword = fileCfg.SSHPassword
	}
	if !flags.Changed("remote-dir") && fileCfg.RemoteDir != "" {
		cfg.RemoteDir = fileCfg.RemoteDir
	}
	if !flags.Changed("concurrency") && fileCfg.Concurrency != 0 {
		cfg.Concurrency = fileCfg.Concurrency
	}
	if !flags.Changed("timeout") && fileCfg.Timeout != 0 {
		cfg.Timeout = fileCfg.Timeout
	}
	if !flags.Changed("retries") && fileCfg.Retries != 0 {
		cfg.Retries = fileCfg.Retries
	}
	return nil
}

func main() {
	defaultConc := runtime.NumCPU()
	// CLI definition
	root := &cobra.Command{
		Use:     "lldp-check",
		Short:   "Verify LLDP cable mappings",
		PreRunE: initConfig,
		RunE:    runCheck,
	}
	flags := root.PersistentFlags()
	flags.StringVar(&cfg.ConfigFile, "config-file", "", "path to YAML config file")
	flags.StringVar(&cfg.HostsFile, "hosts-file", "hosts.txt", "newline list of hosts")
	flags.StringVar(&cfg.CSVFile, "csv", "expected.csv", "mapping CSV file")
	flags.StringVar(&cfg.OutDir, "json-dir", "lldp_json", "local output directory")
	flags.StringVar(&cfg.SSHUser, "ssh-user", os.Getenv("USER"), "SSH username")
	flags.StringVar(&cfg.KeyFile, "key-file", filepath.Join(os.Getenv("HOME"), ".ssh/id_rsa"), "SSH private key path")
	flags.StringVar(&cfg.SSHPassword, "ssh-password", "", "SSH password (optional)")
	flags.StringVar(&cfg.RemoteDir, "remote-dir", "/tmp", "remote temp directory")
	flags.IntVar(&cfg.Concurrency, "concurrency", defaultConc, "max parallel hosts")
	flags.DurationVar(&cfg.Timeout, "timeout", 15*time.Second, "per-host operation timeout")
	flags.IntVar(&cfg.Retries, "retries", 2, "SSH retry attempts")
	_ = root.Execute()
}

// runCheck orchestrates the checking workflow.
func runCheck(cmd *cobra.Command, args []string) error {
	// validate inputs
	if _, err := os.Stat(cfg.HostsFile); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.CSVFile); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return err
	}
	// init logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	runner, err := NewSSHRunner(cfg.SSHUser, cfg.KeyFile, cfg.SSHPassword)
	if err != nil {
		return err
	}
	hosts, err := readHosts(cfg.HostsFile)
	if err != nil {
		return err
	}
	refs, err := parseCSV(cfg.CSVFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, cfg.Concurrency)
	errs := make(map[string]error)
	var mu sync.Mutex
	for _, host := range hosts {
		h := host
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
			defer cancel()

			remote := filepath.Join(cfg.RemoteDir, fmt.Sprintf("%s-lldp.json", h))
			if _, err := runner.RunCommand(ctx, h, fmt.Sprintf("lldpcli show neighbor -f JSON > %s", remote)); err != nil {
				mu.Lock()
				errs[h] = err
				mu.Unlock()
				runner.CleanupRemote(ctx, h, remote)
				return nil
			}
			if err := runner.FetchFile(ctx, h, remote, filepath.Join(cfg.OutDir, h+"-lldp.json")); err != nil {
				mu.Lock()
				errs[h] = err
				mu.Unlock()
				runner.CleanupRemote(ctx, h, remote)
				return nil
			}
			runner.CleanupRemote(ctx, h, remote)
			if err := checkJSON(filepath.Join(cfg.OutDir, h+"-lldp.json"), h, refs); err != nil {
				mu.Lock()
				errs[h] = err
				mu.Unlock()
				return nil
			}
			return nil
		})
	}
	_ = g.Wait()
	for h, err := range errs {
		logger.Warn("host error", "host", h, "err", err)
	}
	logger.Info("All hosts processed")
	return nil
}

// checkJSON verifies the LLDP JSON against expected data.
func checkJSON(path, host string, refs map[string]map[string]ReferenceEntry) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: cannot open JSON: %w", host, err)
	}
	defer f.Close()
	var data LLDPJSON
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return fmt.Errorf("%s: JSON decode error: %w", host, err)
	}
	exp, ok := refs[host]
	if !ok {
		return fmt.Errorf("%s: no reference entries", host)
	}
	for _, iface := range data.LLDP.Interface {
		rec, exists := exp[iface.IfName]
		if !exists {
			return fmt.Errorf("%s: unexpected interface %s", host, iface.IfName)
		}
		got := iface.Chassis.Name + "/" + iface.Port.ID.Value
		expStr := rec.ExpSwitch + "/" + rec.ExpPort
		if got != expStr {
			return fmt.Errorf("%s: mismatch %s != %s", host, got, expStr)
		}
	}
	return nil
}
