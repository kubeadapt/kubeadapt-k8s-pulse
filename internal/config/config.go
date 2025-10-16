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

const (
	// Boolean string representations
	boolStringTrue = "true"
	boolStringOne  = "1"
)

// Config holds the application configuration
type Config struct {
	// Metrics server configuration
	MetricsPort int    `yaml:"metrics_port" env:"EBPF_METRICS_PORT" default:"9090"`
	MetricsPath string `yaml:"metrics_path" env:"EBPF_METRICS_PATH" default:"/metrics"`

	// Collection configuration
	CollectionInterval time.Duration `yaml:"collection_interval" env:"EBPF_COLLECTION_INTERVAL" default:"10s"`
	BatchSize          int           `yaml:"batch_size" env:"EBPF_BATCH_SIZE" default:"100"`
	CleanupInterval    time.Duration `yaml:"cleanup_interval" env:"EBPF_CLEANUP_INTERVAL" default:"5m"`

	// Container discovery
	ContainerDiscovery  string `yaml:"container_discovery" env:"EBPF_CONTAINER_DISCOVERY" default:"kubernetes"`
	KubernetesNamespace string `yaml:"kubernetes_namespace" env:"EBPF_KUBERNETES_NAMESPACE" default:""`
	ProcPath            string `yaml:"proc_path" env:"EBPF_PROC_PATH" default:"/host/proc"`

	// BPF configuration
	BPFMapMaxEntries int  `yaml:"bpf_map_max_entries" env:"EBPF_BPF_MAP_MAX_ENTRIES" default:"10240"`
	BPFPerCPUMaps    bool `yaml:"bpf_per_cpu_maps" env:"EBPF_BPF_PER_CPU_MAPS" default:"true"`

	// Connection tracking configuration (LRU auto-eviction only, no manual cleanup)
	ConnectionTracking            bool          `yaml:"connection_tracking" env:"EBPF_CONNECTION_TRACKING" default:"true"`
	TopFlowsLimit                 int           `yaml:"top_flows_limit" env:"EBPF_TOP_FLOWS_LIMIT" default:"1000"`
	ConnectionAggregationInterval time.Duration `yaml:"connection_aggregation_interval" env:"EBPF_CONNECTION_AGGREGATION_INTERVAL" default:"30s"`

	// Metric cardinality control
	EnableServiceMetrics bool `yaml:"enable_service_metrics" env:"EBPF_ENABLE_SERVICE_METRICS" default:"true"`
	ServiceMetricsTopK   int  `yaml:"service_metrics_top_k" env:"EBPF_SERVICE_METRICS_TOP_K" default:"100"` // Number of top service pairs to track in detail

	// Logging configuration
	LogLevel  string `yaml:"log_level" env:"EBPF_LOG_LEVEL" default:"info"`
	LogFormat string `yaml:"log_format" env:"EBPF_LOG_FORMAT" default:"json"`

	// Node information
	NodeName string `yaml:"node_name" env:"NODE_NAME" default:""`

	// Debug options
	Debug           bool          `yaml:"debug" env:"EBPF_DEBUG" default:"false"`
	EnableProfiling bool          `yaml:"enable_profiling" env:"EBPF_ENABLE_PROFILING" default:"false"`
	ProfilingPort   int           `yaml:"profiling_port" env:"EBPF_PROFILING_PORT" default:"6060"`
	DumpBPFMaps     bool          `yaml:"dump_bpf_maps" env:"EBPF_DUMP_BPF_MAPS" default:"false"`
	DumpMapInterval time.Duration `yaml:"dump_map_interval" env:"EBPF_DUMP_MAP_INTERVAL" default:"60s"`
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
	c.MetricsPort = 9090
	c.MetricsPath = "/metrics"
	c.CollectionInterval = 10 * time.Second
	c.BatchSize = 100
	c.CleanupInterval = 5 * time.Minute
	c.ContainerDiscovery = "kubernetes"
	c.BPFMapMaxEntries = 10240
	c.BPFPerCPUMaps = true
	c.ConnectionTracking = true
	c.TopFlowsLimit = 1000
	c.ConnectionAggregationInterval = 30 * time.Second
	c.EnableServiceMetrics = true
	c.ServiceMetricsTopK = 100
	c.LogLevel = "info"
	c.LogFormat = "json"
	c.ProfilingPort = 6060
	c.DumpMapInterval = 60 * time.Second
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
	if v := os.Getenv("EBPF_METRICS_PATH"); v != "" {
		c.MetricsPath = v
	}

	// Collection configuration
	if v := os.Getenv("EBPF_COLLECTION_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.CollectionInterval = d
		}
	}
	if v := os.Getenv("EBPF_BATCH_SIZE"); v != "" {
		if size, err := strconv.Atoi(v); err == nil {
			c.BatchSize = size
		}
	}
	if v := os.Getenv("EBPF_CLEANUP_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.CleanupInterval = d
		}
	}

	// Container discovery
	if v := os.Getenv("EBPF_CONTAINER_DISCOVERY"); v != "" {
		c.ContainerDiscovery = v
	}
	if v := os.Getenv("EBPF_KUBERNETES_NAMESPACE"); v != "" {
		c.KubernetesNamespace = v
	}
	if v := os.Getenv("EBPF_PROC_PATH"); v != "" {
		c.ProcPath = v
	}

	// BPF configuration
	if v := os.Getenv("EBPF_BPF_MAP_MAX_ENTRIES"); v != "" {
		if entries, err := strconv.Atoi(v); err == nil {
			c.BPFMapMaxEntries = entries
		}
	}
	if v := os.Getenv("EBPF_BPF_PER_CPU_MAPS"); v != "" {
		c.BPFPerCPUMaps = v == boolStringTrue || v == boolStringOne
	}

	// Connection tracking configuration
	if v := os.Getenv("EBPF_CONNECTION_TRACKING"); v != "" {
		c.ConnectionTracking = v == boolStringTrue || v == boolStringOne
	}
	if v := os.Getenv("EBPF_TOP_FLOWS_LIMIT"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil {
			c.TopFlowsLimit = limit
		}
	}
	if v := os.Getenv("EBPF_CONNECTION_AGGREGATION_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.ConnectionAggregationInterval = d
		}
	}

	// Metric cardinality control
	if v := os.Getenv("EBPF_ENABLE_SERVICE_METRICS"); v != "" {
		c.EnableServiceMetrics = v == boolStringTrue || v == boolStringOne
	}
	if v := os.Getenv("EBPF_SERVICE_METRICS_TOP_K"); v != "" {
		if topK, err := strconv.Atoi(v); err == nil {
			c.ServiceMetricsTopK = topK
		}
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
		c.Debug = v == boolStringTrue || v == boolStringOne
	}
	if v := os.Getenv("EBPF_ENABLE_PROFILING"); v != "" {
		c.EnableProfiling = v == boolStringTrue || v == boolStringOne
	}
	if v := os.Getenv("EBPF_PROFILING_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			c.ProfilingPort = port
		}
	}
	if v := os.Getenv("EBPF_DUMP_BPF_MAPS"); v != "" {
		c.DumpBPFMaps = v == boolStringTrue || v == boolStringOne
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

	// Validate batch size
	if c.BatchSize < 1 {
		return fmt.Errorf("batch size must be positive: %d", c.BatchSize)
	}

	// Validate container discovery
	switch c.ContainerDiscovery {
	case "kubernetes", "proc", "none":
		// Valid
	default:
		return fmt.Errorf("invalid container discovery method: %s", c.ContainerDiscovery)
	}

	// Validate log level
	if _, err := zapcore.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("invalid log level: %s", c.LogLevel)
	}

	// Validate BPF map size
	if c.BPFMapMaxEntries < 100 {
		return fmt.Errorf("BPF map max entries too small: %d", c.BPFMapMaxEntries)
	}

	return nil
}

// BuildLogger builds a zap logger based on configuration
func (c *Config) BuildLogger() (*zap.Logger, error) {
	var cfg zap.Config

	// Choose preset based on format
	if c.LogFormat == "json" {
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

	// Build logger
	logger, err := cfg.Build()
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
	sb.WriteString(fmt.Sprintf("  Container Discovery: %s\n", c.ContainerDiscovery))
	sb.WriteString(fmt.Sprintf("  Kubernetes Namespace: %s\n", c.KubernetesNamespace))
	sb.WriteString(fmt.Sprintf("  BPF Map Max Entries: %d\n", c.BPFMapMaxEntries))
	sb.WriteString(fmt.Sprintf("  Log Level: %s\n", c.LogLevel))
	sb.WriteString(fmt.Sprintf("  Log Format: %s\n", c.LogFormat))
	sb.WriteString(fmt.Sprintf("  Node Name: %s\n", c.NodeName))
	sb.WriteString(fmt.Sprintf("  Debug: %t\n", c.Debug))
	return sb.String()
}
