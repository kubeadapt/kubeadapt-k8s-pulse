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
	// CollectionInterval is how often BPF maps are read and metrics exported
	CollectionInterval time.Duration `yaml:"collection_interval" env:"EBPF_COLLECTION_INTERVAL" default:"25s"`

	// ProcPath for host /proc filesystem access
	ProcPath string `yaml:"proc_path" env:"EBPF_PROC_PATH" default:"/host/proc"`

	// Connection tracking configuration (read-then-delete pattern with overflow ringbuffer)
	ConnectionTracking bool `yaml:"connection_tracking" env:"EBPF_CONNECTION_TRACKING" default:"true"`

	// Logging configuration
	LogLevel  string `yaml:"log_level" env:"EBPF_LOG_LEVEL" default:"info"`
	LogFormat string `yaml:"log_format" env:"EBPF_LOG_FORMAT" default:"json"`

	// Node information
	NodeName string `yaml:"node_name" env:"NODE_NAME" default:""`

	// Debug options
	EnableProfiling bool `yaml:"enable_profiling" env:"EBPF_ENABLE_PROFILING" default:"false"`
	ProfilingPort   int  `yaml:"profiling_port" env:"EBPF_PROFILING_PORT" default:"6060"`
	// DumpBPFMaps triggers map dumping BEFORE deletion in collector (synchronized with collection cycle)
	// When enabled, dumps first 10 connection entries before read-then-delete operation
	DumpBPFMaps bool `yaml:"dump_bpf_maps" env:"EBPF_DUMP_BPF_MAPS" default:"false"`
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
	c.ConnectionTracking = true
	c.LogLevel = "info"
	c.LogFormat = LogFormatJSON
	c.ProfilingPort = DefaultProfilingPort
}

// loadFromFile loads configuration from a YAML file
func (c *Config) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		// Handle missing file gracefully - use defaults
		if os.IsNotExist(err) {
			return nil
		}
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

	// Validate profiling port if profiling is enabled
	if c.EnableProfiling {
		if c.ProfilingPort < 1 || c.ProfilingPort > 65535 {
			return fmt.Errorf("invalid profiling port: %d", c.ProfilingPort)
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
		"service": "kubeadapt-k8s-pulse",
		"node":    c.NodeName,
	}

	// Disable sampling when log level is debug (we want to see everything)
	// Sampling is production optimization that groups repetitive messages
	// Not needed in debug mode where thoroughness > performance
	if level == zapcore.DebugLevel {
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
	sb.WriteString(fmt.Sprintf("  Connection Tracking: %t\n", c.ConnectionTracking))
	sb.WriteString(fmt.Sprintf("  Log Level: %s\n", c.LogLevel))
	sb.WriteString(fmt.Sprintf("  Log Format: %s\n", c.LogFormat))
	sb.WriteString(fmt.Sprintf("  Node Name: %s\n", c.NodeName))
	if c.EnableProfiling {
		sb.WriteString(fmt.Sprintf("  Profiling Enabled: true (port %d)\n", c.ProfilingPort))
	}
	if c.DumpBPFMaps {
		sb.WriteString("  BPF Map Dumping: enabled (synchronized with collector)\n")
	}
	return sb.String()
}

// GetDumpBPFMaps returns the DumpBPFMaps flag (for collector interface)
func (c *Config) GetDumpBPFMaps() bool {
	return c.DumpBPFMaps
}
