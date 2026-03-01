// Package config provides configuration management for the DDoS controller.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration struct loaded from YAML.
type Config struct {
	Interface    string       `yaml:"interface"`
	BPFObject    string       `yaml:"bpf_object"`
	PollInterval Duration     `yaml:"poll_interval"`
	Model        ModelConfig  `yaml:"model"`
	Alerting     AlertConfig  `yaml:"alerting"`
	InfluxDB     InfluxConfig `yaml:"influxdb"`
	Blacklist    BlacklistCfg `yaml:"blacklist"`
}

// ModelConfig specifies the ONNX model path and inference settings.
type ModelConfig struct {
	Path      string  `yaml:"path"`
	Threshold float32 `yaml:"threshold"`
}

// AlertConfig controls how alerts are dispatched.
type AlertConfig struct {
	LogFile    string `yaml:"log_file"`
	WebhookURL string `yaml:"webhook_url"`
}

// InfluxConfig holds InfluxDB connection parameters.
type InfluxConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Token   string `yaml:"token"`
	Org     string `yaml:"org"`
	Bucket  string `yaml:"bucket"`
}

// BlacklistCfg controls automatic mitigation behaviour.
type BlacklistCfg struct {
	Enabled bool     `yaml:"enabled"`
	TTLS    Duration `yaml:"ttl"`
}

// Duration wraps time.Duration to support YAML unmarshalling of "500ms", "2s", etc.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		// Sensible defaults
		Interface:    "eth0",
		BPFObject:    "bpf/xdp_prog.o",
		PollInterval: Duration{500 * time.Millisecond},
		Model: ModelConfig{
			Path:      "ml/models/model.onnx",
			Threshold: 0.85,
		},
		Blacklist: BlacklistCfg{
			Enabled: true,
			TTLS:    Duration{60 * time.Second},
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
