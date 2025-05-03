package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"
	"log/slog"
)

var logger *slog.Logger

// initLogger sets up a JSON slog.Logger to stdout or a specified file.
// Returns the logger and an *os.File if a log file was opened (nil otherwise).
func initLogger(logFile string) (*slog.Logger, *os.File) {
	var handler slog.Handler
	var f *os.File
	if logFile != "" {
		var err error
		f, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", logFile, err)
			os.Exit(1)
		}
		handler = slog.NewJSONHandler(f, &slog.HandlerOptions{})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})
	}
	return slog.New(handler), f
}

func main() {
	// Flags
	hostsFile := flag.String("hosts-file", "hosts.txt", "File with one hostname or IP per line")
	csvPath := flag.String("csv", "expected.csv", "Path to expected CSV file")
	jsonDir := flag.String("json-dir", "./lldp_json", "Local directory to store LLDP JSON files")
	logFile := flag.String("log-file", "", "JSON log output file (defaults to stdout)")
	flag.Parse()

	// Initialize structured logging
	var logFD *os.File
	logger, logFD = initLogger(*logFile)
	if logFD != nil {
		defer logFD.Close()
	}

	// Ensure output directory exists
	if err := os.MkdirAll(*jsonDir, 0755); err != nil {
		logger.Error("Failed to create JSON dir", "dir", *jsonDir, "err", err)
		os.Exit(1)
	}

	// Load expected references
	references, err := loadReferences(*csvPath)
	if err != nil {
		logger.Error("Failed to load CSV", "csv", *csvPath, "err", err)
		os.Exit(1)
	}

	// Read hosts list
	hosts, err := readHosts(*hostsFile)
	if err != nil {
		logger.Error("Failed to read hosts file", "file", *hostsFile, "err", err)
		os.Exit(1)
	}

	// Parallel LLDP checks
	var g errgroup.Group
	for _, host := range hosts {
		host := host
		g.Go(func() error {
			remotePath := fmt.Sprintf("/tmp/%s-lldp.json", host)
			// SSH to generate LLDP JSON
			if out, err := exec.Command("ssh", host,
				"lldpcli show neighbor -f JSON > "+remotePath).CombinedOutput(); err != nil {
				logger.Error("SSH command failed", "host", host, "err", err, "output", string(out))
				return err
			}

			// SCP JSON back to local
			localPath := filepath.Join(*jsonDir, host+"-lldp.json")
			if out, err := exec.Command("scp", host+":"+remotePath, localPath).CombinedOutput(); err != nil {
				logger.Error("SCP failed", "host", host, "err", err, "output", string(out))
				return err
			}

			// Compare LLDP data
			if err := checkHost(localPath, host, references); err != nil {
				logger.Error("Host check failed", "host", host, "err", err)
				return err
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		logger.Error("Error during LLDP checks", "err", err)
		os.Exit(1)
	}
	logger.Info("Completed LLDP verification for all hosts")
}

// readHosts loads a newline-delimited host file.
func readHosts(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	hosts := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	return hosts, scanner.Err()
}

// loadReferences reads expected.csv into a nested map.
func loadReferences(path string) (map[string]map[string]ReferenceEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	recs, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	refs := make(map[string]map[string]ReferenceEntry)
	for i, rec := range recs {
		if i == 0 {
			continue
		}
		if len(rec) < 4 {
			logger.Warn("Skipping malformed CSV line", "line", i+1, "record", rec)
			continue
		}
		h := strings.TrimSpace(rec[0])
		iface := strings.TrimSpace(rec[1])
		sw := strings.TrimSpace(rec[2])
		port := strings.TrimSpace(rec[3])

		if refs[h] == nil {
			refs[h] = make(map[string]ReferenceEntry)
		}
		refs[h][iface] = ReferenceEntry{h, iface, sw, port}
	}
	return refs, nil
}

// checkHost parses local JSON, compares to refs, returns error on issues.
func checkHost(jsonFile, hostname string, refs map[string]map[string]ReferenceEntry) error {
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("%s: error reading JSON: %w", hostname, err)
	}

	var lj LLDPJSON
	if err := json.Unmarshal(data, &lj); err != nil {
		return fmt.Errorf("%s: JSON unmarshal error: %w", hostname, err)
	}

	expectedMap, ok := refs[hostname]
	if !ok {
		logger.Warn("No reference entries for host", "host", hostname)
		return nil
	}

	for _, intf := range lj.LLDP.Interface {
		re, found := expectedMap[intf.IfName]
		if !found {
			logger.Warn("Unexpected interface", "host", hostname, "iface", intf.IfName)
			continue
		}

		actSw := intf.Chassis.Name
		actPort := intf.Port.ID.Value

		if actSw != re.ExpSwitch || actPort != re.ExpPort {
			logger.Warn("Mismatch",
				"host", hostname,
				"iface", intf.IfName,
				"got_switch", actSw,
				"got_port", actPort,
				"expected_switch", re.ExpSwitch,
				"expected_port", re.ExpPort,
			)
		} else {
			logger.Info("OK",
				"host", hostname,
				"iface", intf.IfName,
				"switch", actSw,
				"port", actPort,
			)
		}
	}
	return nil
}
