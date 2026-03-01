// tests/config_test.go — Tests for configuration loading

package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aliciamew/ddos-early-warning/internal/config"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "test_config.yaml")

	content := `
interface: "lo"
bpf_object: "test.o"
poll_interval: "250ms"
model:
  path: "test_model.onnx"
  threshold: 0.90
alerting:
  log_file: "test_alerts.log"
influxdb:
  enabled: false
blacklist:
  enabled: true
  ttl: "30s"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Interface != "lo" {
		t.Errorf("Interface: got %q, want 'lo'", cfg.Interface)
	}

	if cfg.PollInterval.Duration != 250*time.Millisecond {
		t.Errorf("PollInterval: got %v, want 250ms", cfg.PollInterval.Duration)
	}

	if cfg.Model.Threshold != 0.90 {
		t.Errorf("Threshold: got %f, want 0.90", cfg.Model.Threshold)
	}

	if cfg.Blacklist.TTLS.Duration != 30*time.Second {
		t.Errorf("Blacklist TTL: got %v, want 30s", cfg.Blacklist.TTLS.Duration)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "minimal.yaml")

	// Minimal config — should use defaults
	os.WriteFile(cfgPath, []byte("{}"), 0644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Interface != "eth0" {
		t.Errorf("Default interface: got %q, want 'eth0'", cfg.Interface)
	}

	if cfg.PollInterval.Duration != 500*time.Millisecond {
		t.Errorf("Default poll interval: got %v, want 500ms", cfg.PollInterval.Duration)
	}

	if cfg.Model.Threshold != 0.85 {
		t.Errorf("Default threshold: got %f, want 0.85", cfg.Model.Threshold)
	}
}
