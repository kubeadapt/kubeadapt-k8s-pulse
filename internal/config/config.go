package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v2"
)

// Note: Constants moved to constants.go for better organization

// Config holds the application configuration
type Config struct {
	// Metrics server configuration
	MetricsPort int `yaml:"metrics_port" env:"EBPF_METRICS_PORT" default:"9090"`

	// Collection configuration
	// CRITICAL: CollectionInterval must be SHORTER than Prometheus scrape interval
	// to ensure only ONE collection happens between scrapes (prevents data loss from gauge overwrites).
	// Default 25s assumes 30s Prometheus scrape interval (leaving 5s safety buffer).
	// If Prometheus scrapes at different interval, adjust this value accordingly:
	//   - For 60s scrapes: use 55s collection interval
	//   - For 15s scrapes: use 12s collection interval
	// Rule: collection_interval = scrape_interval - 5s buffer
	CollectionInterval time.Duration `yaml:"collection_interval" env:"EBPF_COLLECTION_INTERVAL" default:"25s"`

	// ProcPath for container discovery (currently not used - kept for future use)
	ProcPath string `yaml:"proc_path" env:"EBPF_PROC_PATH" default:"/host/proc"`

	// Network namespace filtering mode
	// Controls which processes are tracked for network metrics
	// EBPF_NETNS_FILTER_MODE: Network namespace filtering strategy
	//   - "default": Track all Kubernetes pods (including hostNetwork:true like node-exporter)
	//                Filter only host system processes (kubelet, containerd, sshd)
	//                Uses simple cgroup check (cgroup_id != 1)
	//                RECOMMENDED for most use cases
	//   - "strict":  Track only pods with separate network namespaces (hostNetwork:false)
	//                Filter host processes AND hostNetwork:true pods
	//                Uses CO-RE network namespace inode comparison
	//                Use when you want to exclude hostNetwork pods from tracking
	//   - "disabled": Track everything (no filtering at all)
	//                 Useful for debugging - shows all network activity including host processes
	NetnsFilterMode string `yaml:"netns_filter_mode" env:"EBPF_NETNS_FILTER_MODE" default:"default"`

	// Connection tracking configuration (read-then-delete pattern with overflow ringbuffer)
	ConnectionTracking bool `yaml:"connection_tracking" env:"EBPF_CONNECTION_TRACKING" default:"true"`

	// Logging configuration
	LogLevel  string `yaml:"log_level" env:"EBPF_LOG_LEVEL" default:"info"`
	LogFormat string `yaml:"log_format" env:"EBPF_LOG_FORMAT" default:"json"`

	// Node information
	NodeName string `yaml:"node_name" env:"NODE_NAME" default:""`

	// Debug options
	Debug           bool `yaml:"debug" env:"EBPF_DEBUG" default:"false"`
	EnableProfiling bool `yaml:"enable_profiling" env:"EBPF_ENABLE_PROFILING" default:"false"`
	ProfilingPort   int  `yaml:"profiling_port" env:"EBPF_PROFILING_PORT" default:"6060"`
	DumpBPFMaps     bool `yaml:"dump_bpf_maps" env:"EBPF_DUMP_BPF_MAPS" default:"false"`
	// DumpMapInterval must be < CollectionInterval (25s) to see data before deletion
	// 15s allows 1-2 dumps per collection cycle, showing live data
	DumpMapInterval time.Duration `yaml:"dump_map_interval" env:"EBPF_DUMP_MAP_INTERVAL" default:"15s"`
}

// Load loads configuration from file and environment
func Load(configFile string) (*Config, error) {
	cfg := &Config{}

	// Set defaults
	cfg.setDefaults()

	// Load from file if provided
	if configFile != "" {
		if err := cfg.loadFromFile(configFile); err != nil {
			return nil, fmt.Errorf("loading config file: %w", err)
		}
	}

	// Override with environment variables
	cfg.loadFromEnv()

	// Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// setDefaults sets default values
func (c *Config) setDefaults() {
	c.MetricsPort = DefaultMetricsPort
	c.CollectionInterval = DefaultCollectionInterval
	c.ProcPath = DefaultProcPath
	c.NetnsFilterMode = NetnsFilterModeDefault
	c.ConnectionTracking = true
	c.LogLevel = "info"
	c.LogFormat = LogFormatJSON
	c.ProfilingPort = DefaultProfilingPort
	c.DumpMapInterval = DefaultDumpMapInterval
}

// loadFromFile loads configuration from a YAML file
func (c *Config) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("unmarshaling YAML: %w", err)
	}

	return nil
}

// loadFromEnv loads configuration from environment variables
func (c *Config) loadFromEnv() {
	// Metrics configuration
	if v := os.Getenv("EBPF_METRICS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			c.MetricsPort = port
		}
	}

	// Collection configuration
	if v := os.Getenv("EBPF_COLLECTION_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.CollectionInterval = d
		}
	}

	// ProcPath configuration
	if v := os.Getenv("EBPF_PROC_PATH"); v != "" {
		c.ProcPath = v
	}

	// Network namespace filtering
	if v := os.Getenv("EBPF_NETNS_FILTER_MODE"); v != "" {
		c.NetnsFilterMode = v
	}

	// Connection tracking configuration
	if v := os.Getenv("EBPF_CONNECTION_TRACKING"); v != "" {
		c.ConnectionTracking = v == BoolStringTrue || v == BoolStringOne
	}

	// Logging configuration
	if v := os.Getenv("EBPF_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("EBPF_LOG_FORMAT"); v != "" {
		c.LogFormat = v
	}

	// Node information
	if v := os.Getenv("NODE_NAME"); v != "" {
		c.NodeName = v
	}

	// Debug options
	if v := os.Getenv("EBPF_DEBUG"); v != "" {
		c.Debug = v == BoolStringTrue || v == BoolStringOne
	}
	if v := os.Getenv("EBPF_ENABLE_PROFILING"); v != "" {
		c.EnableProfiling = v == BoolStringTrue || v == BoolStringOne
	}
	if v := os.Getenv("EBPF_PROFILING_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			c.ProfilingPort = port
		}
	}
	if v := os.Getenv("EBPF_DUMP_BPF_MAPS"); v != "" {
		c.DumpBPFMaps = v == BoolStringTrue || v == BoolStringOne
	}
	if v := os.Getenv("EBPF_DUMP_MAP_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.DumpMapInterval = d
		}
	}
}

// validate validates the configuration
func (c *Config) validate() error {
	// Validate metrics port
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return fmt.Errorf("invalid metrics port: %d", c.MetricsPort)
	}

	// Validate collection interval
	if c.CollectionInterval < time.Second {
		return fmt.Errorf("collection interval too short: %s", c.CollectionInterval)
	}

	// Validate log level
	if _, err := zapcore.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("invalid log level: %s", c.LogLevel)
	}

	// Validate network namespace filter mode
	switch c.NetnsFilterMode {
	case NetnsFilterModeDefault, NetnsFilterModeStrict, NetnsFilterModeDisabled:
		// Valid modes
	default:
		return fmt.Errorf("invalid netns filter mode: %s (must be '%s', '%s', or '%s')",
			c.NetnsFilterMode, NetnsFilterModeDefault, NetnsFilterModeStrict, NetnsFilterModeDisabled)
	}

	// Validate profiling port if profiling is enabled
	if c.EnableProfiling {
		if c.ProfilingPort < 1 || c.ProfilingPort > 65535 {
			return fmt.Errorf("invalid profiling port: %d", c.ProfilingPort)
		}
	}

	// Validate dump interval if map dumping is enabled
	if c.DumpBPFMaps {
		if c.DumpMapInterval < time.Second {
			return fmt.Errorf("dump map interval too short: %s", c.DumpMapInterval)
		}
	}

	return nil
}

// BuildLogger builds a zap logger based on configuration
func (c *Config) BuildLogger() (*zap.Logger, error) {
	var cfg zap.Config

	// Choose preset based on format
	if c.LogFormat == LogFormatJSON {
		cfg = zap.NewProductionConfig()
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Set log level
	level, err := zapcore.ParseLevel(c.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("parsing log level: %w", err)
	}
	cfg.Level = zap.NewAtomicLevelAt(level)

	// Add fields
	cfg.InitialFields = map[string]interface{}{
		"service": "ebpf-agent",
		"node":    c.NodeName,
	}

	// Disable sampling in debug mode
	if c.Debug {
		cfg.Sampling = nil
	}

	// Build logger with synchronized output to prevent log interleaving
	// from multiple goroutines (overflow handler, collector, metrics server)
	logger, err := cfg.Build(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		// Get the encoder from the existing core
		encoder := zapcore.NewJSONEncoder(cfg.EncoderConfig)
		if c.LogFormat != LogFormatJSON {
			encoder = zapcore.NewConsoleEncoder(cfg.EncoderConfig)
		}

		// Wrap stdout with Lock() to ensure atomic writes
		syncedWriter := zapcore.Lock(os.Stdout)

		// Create new core with locked writer
		return zapcore.NewCore(
			encoder,
			syncedWriter,
			cfg.Level,
		)
	}))
	if err != nil {
		return nil, fmt.Errorf("building logger: %w", err)
	}

	// Replace global logger
	zap.ReplaceGlobals(logger)

	return logger, nil
}

// String returns a string representation of the config
func (c *Config) String() string {
	var sb strings.Builder
	sb.WriteString("Configuration:\n")
	sb.WriteString(fmt.Sprintf("  Metrics Port: %d\n", c.MetricsPort))
	sb.WriteString(fmt.Sprintf("  Collection Interval: %s\n", c.CollectionInterval))
	sb.WriteString(fmt.Sprintf("  Network Namespace Filter Mode: %s\n", c.NetnsFilterMode))
	sb.WriteString(fmt.Sprintf("  Connection Tracking: %t\n", c.ConnectionTracking))
	sb.WriteString(fmt.Sprintf("  Log Level: %s\n", c.LogLevel))
	sb.WriteString(fmt.Sprintf("  Log Format: %s\n", c.LogFormat))
	sb.WriteString(fmt.Sprintf("  Node Name: %s\n", c.NodeName))
	sb.WriteString(fmt.Sprintf("  Debug: %t\n", c.Debug))
	if c.EnableProfiling {
		sb.WriteString(fmt.Sprintf("  Profiling Enabled: true (port %d)\n", c.ProfilingPort))
	}
	if c.DumpBPFMaps {
		sb.WriteString(fmt.Sprintf("  BPF Map Dumping: enabled (interval %s)\n", c.DumpMapInterval))
	}
	return sb.String()
}
