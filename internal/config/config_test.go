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

	if !cfg.ConnectionTracking {
		t.Error("ConnectionTracking = false, expected true")
	}

	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, expected %q", cfg.LogLevel, "info")
	}

	if cfg.DumpBPFMaps {
		t.Error("DumpBPFMaps = true, expected false (default)")
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
	if err := os.Setenv("EBPF_CONNECTION_TRACKING", "false"); err != nil {
		t.Fatalf("Failed to set EBPF_CONNECTION_TRACKING: %v", err)
	}
	if err := os.Setenv("EBPF_LOG_LEVEL", "debug"); err != nil {
		t.Fatalf("Failed to set EBPF_LOG_LEVEL: %v", err)
	}
	if err := os.Setenv("EBPF_DUMP_BPF_MAPS", "true"); err != nil {
		t.Fatalf("Failed to set EBPF_DUMP_BPF_MAPS: %v", err)
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

	if cfg.ConnectionTracking {
		t.Error("ConnectionTracking = true, expected false")
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, expected %q", cfg.LogLevel, "debug")
	}

	if !cfg.DumpBPFMaps {
		t.Error("DumpBPFMaps = false, expected true")
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
connection_tracking: false
log_level: warn
dump_bpf_maps: true
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

// TestLoad_InvalidDuration tests invalid duration string parsing
func TestLoad_InvalidDuration(t *testing.T) {
	clearTestEnv(t)

	// Set invalid duration format
	if err := os.Setenv("EBPF_COLLECTION_INTERVAL", "not-a-duration"); err != nil {
		t.Fatalf("Failed to set EBPF_COLLECTION_INTERVAL: %v", err)
	}
	defer clearTestEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Should fall back to default when parsing fails
	if cfg.CollectionInterval != DefaultCollectionInterval {
		t.Errorf("CollectionInterval = %v, expected default %v for invalid duration",
			cfg.CollectionInterval, DefaultCollectionInterval)
	}
}

// TestLoad_PortBoundaries tests port number edge cases
func TestLoad_PortBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		port        string
		shouldError bool
	}{
		{"minimum valid port", "1", false},
		{"low privileged port", "1024", false},
		{"maximum valid port", "65535", false},
		{"port too high", "65536", true},
		{"port zero", "0", true},
		{"negative port", "-1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearTestEnv(t)

			if err := os.Setenv("EBPF_METRICS_PORT", tt.port); err != nil {
				t.Fatalf("Failed to set EBPF_METRICS_PORT: %v", err)
			}
			defer clearTestEnv(t)

			cfg, err := Load("")
			// Load() calls validate() internally, so invalid ports cause Load() to error
			if (err != nil) != tt.shouldError {
				t.Errorf("Load() error = %v, shouldError = %v for port %s",
					err, tt.shouldError, tt.port)
				return
			}

			// For valid ports, verify the config was loaded correctly
			if !tt.shouldError && cfg == nil {
				t.Error("Load() returned nil config for valid port")
			}
		})
	}
}

// TestLoad_MissingConfigFile tests behavior when config file doesn't exist
func TestLoad_MissingConfigFile(t *testing.T) {
	clearTestEnv(t)
	defer clearTestEnv(t)

	// Load with non-existent file path
	cfg, err := Load("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("Load() should not error on missing file, got: %v", err)
	}

	// Should use defaults when file doesn't exist
	if cfg.MetricsPort != DefaultMetricsPort {
		t.Errorf("MetricsPort = %d, expected default %d when file missing",
			cfg.MetricsPort, DefaultMetricsPort)
	}

	if cfg.CollectionInterval != DefaultCollectionInterval {
		t.Errorf("CollectionInterval = %v, expected default %v when file missing",
			cfg.CollectionInterval, DefaultCollectionInterval)
	}
}

// TestLoad_MalformedYAML tests handling of malformed YAML
func TestLoad_MalformedYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "bad-config.yaml")

	// Write malformed YAML
	malformedYAML := `
metrics_port: [invalid
collection_interval: "not properly quoted
	bad indentation
`
	if err := os.WriteFile(configPath, []byte(malformedYAML), 0644); err != nil {
		t.Fatalf("Failed to write malformed config: %v", err)
	}

	clearTestEnv(t)
	defer clearTestEnv(t)

	// Should return error for malformed YAML
	_, err := Load(configPath)
	if err == nil {
		t.Error("Load() should return error for malformed YAML")
	}
}

// TestLoad_CollectionIntervalBoundaries tests collection interval edge cases
func TestLoad_CollectionIntervalBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		interval    string
		shouldError bool
		expectedVal time.Duration
	}{
		{"exactly minimum", "1s", false, 1 * time.Second},
		{"below minimum", "500ms", true, 0},
		{"standard value", "10s", false, 10 * time.Second},
		{"large value", "5m", false, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearTestEnv(t)

			if err := os.Setenv("EBPF_COLLECTION_INTERVAL", tt.interval); err != nil {
				t.Fatalf("Failed to set interval: %v", err)
			}
			defer clearTestEnv(t)

			cfg, err := Load("")
			// Load() calls validate() internally, so invalid intervals cause Load() to error
			if (err != nil) != tt.shouldError {
				t.Errorf("Load() error = %v, shouldError = %v for interval %s",
					err, tt.shouldError, tt.interval)
				return
			}

			// For valid intervals, verify the value was loaded correctly
			if !tt.shouldError {
				if cfg == nil {
					t.Error("Load() returned nil config for valid interval")
					return
				}
				if cfg.CollectionInterval != tt.expectedVal {
					t.Errorf("CollectionInterval = %v, expected %v",
						cfg.CollectionInterval, tt.expectedVal)
				}
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
		"EBPF_CONNECTION_TRACKING",
		"EBPF_LOG_LEVEL",
		"EBPF_LOG_FORMAT",
		"NODE_NAME",
		"EBPF_DEBUG",
		"EBPF_ENABLE_PROFILING",
		"EBPF_PROFILING_PORT",
		"EBPF_DUMP_BPF_MAPS",
	}
	for _, env := range envVars {
		if err := os.Unsetenv(env); err != nil {
			t.Logf("Warning: Failed to unset %s: %v", env, err)
		}
	}
}
