package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear any environment variables that might affect the test
	clearTestEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify defaults
	if cfg.MetricsPort != DefaultMetricsPort {
		t.Errorf("MetricsPort = %d, expected %d", cfg.MetricsPort, DefaultMetricsPort)
	}

	if cfg.CollectionInterval != DefaultCollectionInterval {
		t.Errorf("CollectionInterval = %v, expected %v", cfg.CollectionInterval, DefaultCollectionInterval)
	}

	if cfg.NetnsFilterMode != NetnsFilterModeDefault {
		t.Errorf("NetnsFilterMode = %q, expected %q", cfg.NetnsFilterMode, NetnsFilterModeDefault)
	}

	if !cfg.ConnectionTracking {
		t.Error("ConnectionTracking = false, expected true")
	}

	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, expected %q", cfg.LogLevel, "info")
	}

	if cfg.DumpMapInterval != DefaultDumpMapInterval {
		t.Errorf("DumpMapInterval = %v, expected %v", cfg.DumpMapInterval, DefaultDumpMapInterval)
	}
}

func TestLoad_EnvironmentOverrides(t *testing.T) {
	// Clear any environment variables that might affect the test
	clearTestEnv(t)

	// Set environment variables
	if err := os.Setenv("EBPF_METRICS_PORT", "8080"); err != nil {
		t.Fatalf("Failed to set EBPF_METRICS_PORT: %v", err)
	}
	if err := os.Setenv("EBPF_COLLECTION_INTERVAL", "30s"); err != nil {
		t.Fatalf("Failed to set EBPF_COLLECTION_INTERVAL: %v", err)
	}
	if err := os.Setenv("EBPF_NETNS_FILTER_MODE", "strict"); err != nil {
		t.Fatalf("Failed to set EBPF_NETNS_FILTER_MODE: %v", err)
	}
	if err := os.Setenv("EBPF_CONNECTION_TRACKING", "false"); err != nil {
		t.Fatalf("Failed to set EBPF_CONNECTION_TRACKING: %v", err)
	}
	if err := os.Setenv("EBPF_LOG_LEVEL", "debug"); err != nil {
		t.Fatalf("Failed to set EBPF_LOG_LEVEL: %v", err)
	}
	if err := os.Setenv("EBPF_DUMP_BPF_MAPS", "true"); err != nil {
		t.Fatalf("Failed to set EBPF_DUMP_BPF_MAPS: %v", err)
	}
	if err := os.Setenv("EBPF_DUMP_MAP_INTERVAL", "10s"); err != nil {
		t.Fatalf("Failed to set EBPF_DUMP_MAP_INTERVAL: %v", err)
	}
	defer clearTestEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify environment overrides
	if cfg.MetricsPort != 8080 {
		t.Errorf("MetricsPort = %d, expected 8080", cfg.MetricsPort)
	}

	if cfg.CollectionInterval != 30*time.Second {
		t.Errorf("CollectionInterval = %v, expected 30s", cfg.CollectionInterval)
	}

	if cfg.NetnsFilterMode != "strict" {
		t.Errorf("NetnsFilterMode = %q, expected %q", cfg.NetnsFilterMode, "strict")
	}

	if cfg.ConnectionTracking {
		t.Error("ConnectionTracking = true, expected false")
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, expected %q", cfg.LogLevel, "debug")
	}

	if !cfg.DumpBPFMaps {
		t.Error("DumpBPFMaps = false, expected true")
	}

	if cfg.DumpMapInterval != 10*time.Second {
		t.Errorf("DumpMapInterval = %v, expected 10s", cfg.DumpMapInterval)
	}
}

func TestLoad_BooleanParsing(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"true string", "true", true},
		{"1 string", "1", true},
		{"false string", "false", false},
		{"0 string", "0", false},
		{"empty string", "", false}, // Uses default (true)
		{"invalid string", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearTestEnv(t)

			if tt.envValue != "" {
				if err := os.Setenv("EBPF_CONNECTION_TRACKING", tt.envValue); err != nil {
					t.Fatalf("Failed to set EBPF_CONNECTION_TRACKING: %v", err)
				}
			}
			defer clearTestEnv(t)

			cfg, err := Load("")
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			// For empty string, we expect default (true)
			if tt.envValue == "" {
				if !cfg.ConnectionTracking {
					t.Errorf("ConnectionTracking = %v, expected true (default)", cfg.ConnectionTracking)
				}
			} else {
				if cfg.ConnectionTracking != tt.expected {
					t.Errorf("ConnectionTracking = %v, expected %v for env=%q", cfg.ConnectionTracking, tt.expected, tt.envValue)
				}
			}
		})
	}
}

func TestLoad_FromFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configYAML := `
metrics_port: 9091
collection_interval: 20s
netns_filter_mode: disabled
connection_tracking: false
log_level: warn
dump_bpf_maps: true
dump_map_interval: 12s
`

	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	clearTestEnv(t)
	defer clearTestEnv(t)

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify file values
	if cfg.MetricsPort != 9091 {
		t.Errorf("MetricsPort = %d, expected 9091", cfg.MetricsPort)
	}

	if cfg.CollectionInterval != 20*time.Second {
		t.Errorf("CollectionInterval = %v, expected 20s", cfg.CollectionInterval)
	}

	if cfg.NetnsFilterMode != "disabled" {
		t.Errorf("NetnsFilterMode = %q, expected %q", cfg.NetnsFilterMode, "disabled")
	}
}

func TestLoad_EnvironmentOverridesFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configYAML := `
metrics_port: 9091
log_level: warn
`

	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	clearTestEnv(t)
	// Environment should override file
	if err := os.Setenv("EBPF_METRICS_PORT", "8080"); err != nil {
		t.Fatalf("Failed to set EBPF_METRICS_PORT: %v", err)
	}
	if err := os.Setenv("EBPF_LOG_LEVEL", "debug"); err != nil {
		t.Fatalf("Failed to set EBPF_LOG_LEVEL: %v", err)
	}
	defer clearTestEnv(t)

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Environment variables should take precedence
	if cfg.MetricsPort != 8080 {
		t.Errorf("MetricsPort = %d, expected 8080 (env should override file)", cfg.MetricsPort)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, expected %q (env should override file)", cfg.LogLevel, "debug")
	}
}

func TestValidate_InvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*Config)
		wantError bool
	}{
		{
			name: "invalid metrics port - too low",
			setupFunc: func(c *Config) {
				c.MetricsPort = 0
			},
			wantError: true,
		},
		{
			name: "invalid metrics port - too high",
			setupFunc: func(c *Config) {
				c.MetricsPort = 70000
			},
			wantError: true,
		},
		{
			name: "invalid collection interval",
			setupFunc: func(c *Config) {
				c.CollectionInterval = 500 * time.Millisecond
			},
			wantError: true,
		},
		{
			name: "invalid log level",
			setupFunc: func(c *Config) {
				c.LogLevel = "invalid"
			},
			wantError: true,
		},
		{
			name: "invalid netns filter mode",
			setupFunc: func(c *Config) {
				c.NetnsFilterMode = "invalid"
			},
			wantError: true,
		},
		{
			name: "valid config",
			setupFunc: func(c *Config) {
				// Use defaults
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.setDefaults()
			tt.setupFunc(cfg)

			err := cfg.validate()
			if (err != nil) != tt.wantError {
				t.Errorf("validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Helper function to clear test environment variables
func clearTestEnv(t *testing.T) {
	t.Helper()
	envVars := []string{
		"EBPF_METRICS_PORT",
		"EBPF_COLLECTION_INTERVAL",
		"EBPF_PROC_PATH",
		"EBPF_NETNS_FILTER_MODE",
		"EBPF_CONNECTION_TRACKING",
		"EBPF_LOG_LEVEL",
		"EBPF_LOG_FORMAT",
		"NODE_NAME",
		"EBPF_DEBUG",
		"EBPF_ENABLE_PROFILING",
		"EBPF_PROFILING_PORT",
		"EBPF_DUMP_BPF_MAPS",
		"EBPF_DUMP_MAP_INTERVAL",
	}
	for _, env := range envVars {
		if err := os.Unsetenv(env); err != nil {
			t.Logf("Warning: Failed to unset %s: %v", env, err)
		}
	}
}
