package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

var logger *slog.Logger

// ReferenceEntry represents a row in the expected CSV.
type ReferenceEntry struct {
	Hostname       string
	LocalInterface string
	ExpSwitch      string
	ExpPort        string
}

// LLDPJSON mirrors lldpcli JSON output.
type LLDPJSON struct {
	LLDP struct {
		Interface []struct {
			IfName  string `json:"ifname"`
			Port    struct { ID struct { Value string `json:"value"` } `json:"id"` } `json:"port"`
			Chassis struct { Name string `json:"name"` } `json:"chassis"`
		} `json:"interface"`
	} `json:"lldp"`
}

// initLogger sets up structured JSON logging to stdout or a file.
func initLogger(path string) (*slog.Logger, *os.File) {
	var handler slog.Handler
	var f *os.File
	if path != "" {
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open log file %s: %v\n", path, err)
			os.Exit(1)
		}
		handler = slog.NewJSONHandler(f, nil)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, nil)
	}
	return slog.New(handler), f
}

func main() {
	// Compute default concurrency based on available CPUs
	defaultConc := runtime.NumCPU()

	// flags
	hostsFile := flag.String("hosts-file", "hosts.txt", "list of hosts to check")
	csvFile := flag.String("csv", "expected.csv", "expected mapping CSV file")
	outDir := flag.String("json-dir", "lldp_json", "directory to store LLDP JSON files")
	logPath := flag.String("log-file", "", "JSON log output file (defaults to stdout)")
	concurrency := flag.Int("concurrency", defaultConc, fmt.Sprintf("max parallel SSH/SCP operations (default %d)", defaultConc))
	sshTimeout := flag.Duration("timeout", 10*time.Second, "per-host SSH/SCP timeout duration")
	flag.Parse()

	// setup logger
	var logF *os.File
	logger, logF = initLogger(*logPath)
	if logF != nil {
		defer logF.Close()
	}

	// ensure output directory
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		logger.Error("failed to create output directory", "dir", *outDir, "err", err)
		os.Exit(1)
	}

	// load CSV references
	refs, err := loadReferences(*csvFile)
	if err != nil {
		logger.Error("failed to load CSV", "file", *csvFile, "err", err)
		os.Exit(1)
	}

	// read host list
	hosts, err := readHosts(*hostsFile)
	if err != nil {
		logger.Error("failed to read hosts file", "file", *hostsFile, "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, *concurrency)

	for _, h := range hosts {
		h := h
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			defer func() { <-sem }()
			return processHost(ctx, h, *outDir, refs, *sshTimeout)
		})
	}

	if err := g.Wait(); err != nil {
		logger.Error("verification failed", "err", err)
		os.Exit(1)
	}
	logger.Info("all hosts verified successfully")
}

// processHost runs SSH and SCP with per-host timeout, then verifies LLDP.
func processHost(parentCtx context.Context, host, outDir string, refs map[string]map[string]ReferenceEntry, timeout time.Duration) error {
	sshCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	remote := fmt.Sprintf("/tmp/%s-lldp.json", host)
	if err := runSSH(sshCtx, host, fmt.Sprintf("lldpcli show neighbor -f JSON > %s", remote)); err != nil {
		return err
	}

	scpCtx, cancelScp := context.WithTimeout(parentCtx, timeout)
	defer cancelScp()
	local := filepath.Join(outDir, host+"-lldp.json")
	if err := runSCP(scpCtx, host, remote, local); err != nil {
		return err
	}

	return checkHost(local, host, refs)
}

// runSSH executes a command over SSH using provided context.
func runSSH(ctx context.Context, host, cmd string) error {
	ex := exec.CommandContext(ctx, "ssh", host, cmd)
	if out, err := ex.CombinedOutput(); err != nil {
		logger.Error("ssh failed", "host", host, "err", err, "out", string(out))
		return err
	}
	return nil
}

// runSCP copies a remote file locally using provided context.
func runSCP(ctx context.Context, host, remote, local string) error {
	ex := exec.CommandContext(ctx, "scp", host+":"+remote, local)
	if out, err := ex.CombinedOutput(); err != nil {
		logger.Error("scp failed", "host", host, "err", err, "out", string(out))
		return err
	}
	return nil
}

// readHosts loads hostnames, skipping blank lines and comments.
func readHosts(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	h := make([]string, 0, 64)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		h = append(h, l)
	}
	return h, s.Err()
}

// loadReferences reads expected CSV into nested map.
func loadReferences(path string) (map[string]map[string]ReferenceEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	refs := make(map[string]map[string]ReferenceEntry)
	if _, err := r.Read(); err != nil {
		return nil, err
	}
	for {
		rec, err := r.Read()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		if len(rec) < 4 {
			logger.Warn("malformed CSV record", "record", rec)
			continue
		}
		h, i, sw, p := strings.TrimSpace(rec[0]), strings.TrimSpace(rec[1]), strings.TrimSpace(rec[2]), strings.TrimSpace(rec[3])
		if refs[h] == nil {
			refs[h] = make(map[string]ReferenceEntry)
		}
		refs[h][i] = ReferenceEntry{h, i, sw, p}
	}
	return refs, nil
}

// checkHost parses JSON file and compares to expected entries.
func checkHost(file, host string, refs map[string]map[string]ReferenceEntry) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("%s read error: %w", host, err)
	}
	defer f.Close()

	var data LLDPJSON
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return fmt.Errorf("%s decode error: %w", host, err)
	}

	exp, ok := refs[host]
	if !ok {
		logger.Warn("no expected data for host", "host", host)
		return nil
	}
	for _, iface := range data.LLDP.Interface {
		rec, ok := exp[iface.IfName]
		if !ok {
			logger.Warn("unexpected interface", "host", host, "iface", iface.IfName)
			continue
		}
		gotSw, gotPr := iface.Chassis.Name, iface.Port.ID.Value
		if gotSw != rec.ExpSwitch || gotPr != rec.ExpPort {
			logger.Warn("mismatch",
				"host", host,
				"iface", iface.IfName,
				"got", fmt.Sprintf("%s/%s", gotSw, gotPr),
				"expected", fmt.Sprintf("%s/%s", rec.ExpSwitch, rec.ExpPort),
			)
		} else {
			logger.Info("match", "host", host, "iface", iface.IfName)
		}
	}
	return nil
}
