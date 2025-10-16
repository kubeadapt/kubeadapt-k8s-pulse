package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"github.com/kubeadapt/ebpf-agent/internal/collector"
	"github.com/kubeadapt/ebpf-agent/internal/config"
	"github.com/kubeadapt/ebpf-agent/internal/metrics"
	"go.uber.org/zap"
)

var (
	// Version information (set by build)
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	// Parse command line flags
	var (
		configFile = flag.String("config", "", "Path to configuration file")
		version    = flag.Bool("version", false, "Print version information")
	)
	flag.Parse()

	// Print version if requested
	if *version {
		fmt.Printf("KubeAdapt eBPF Agent\nVersion: %s\nBuild Time: %s\n", Version, BuildTime)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Build logger based on configuration
	logger, err := cfg.BuildLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build logger: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		// Ignore errors from Sync during shutdown
		_ = logger.Sync()
	}()

	logger.Info("Starting KubeAdapt eBPF Agent",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
	)

	// Check kernel compatibility
	if err := checkKernelCompatibility(); err != nil {
		logger.Fatal("Kernel compatibility check failed", zap.Error(err))
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize BPF manager
	logger.Info("Initializing BPF programs...")
	bpfManager, err := bpf.NewManager(logger)
	if err != nil {
		logger.Fatal("Failed to initialize BPF manager", zap.Error(err))
	}
	defer func() {
		logger.Info("Cleaning up BPF programs...")
		if err := bpfManager.Close(); err != nil {
			logger.Error("Error closing BPF manager", zap.Error(err))
		}
	}()

	// Load and attach BPF programs
	logger.Info("Loading BPF programs...")
	if err := bpfManager.LoadAndAttach(); err != nil {
		logger.Fatal("Failed to load BPF programs", zap.Error(err))
	}
	logger.Info("BPF programs loaded and attached successfully")

	// NOTE: Container discovery and cache removed
	// Pod-level metrics are sufficient since K8s pods share network namespace
	// Backend handles all metadata enrichment (pod names, namespaces, services)

	// Initialize metrics server
	logger.Info("Starting metrics server", zap.Int("port", cfg.MetricsPort))
	metricsServer := metrics.NewServer(cfg.MetricsPort, logger)
	go func() {
		if err := metricsServer.Start(); err != nil {
			logger.Error("Metrics server error", zap.Error(err))
		}
	}()

	// NOTE: Container-level metrics collector removed
	// Raw IP-based connection metrics are sufficient (pod-level, no container granularity)
	// Backend handles all metadata enrichment

	// NOTE: ALL K8s-based aggregation removed (service, namespace, zone, region)
	// Agent exports ONLY raw connection-level metrics (pod IP → pod IP)
	// Backend handles ALL aggregation (service, namespace, zone, region, workload)

	// Initialize connection collector for map utilization tracking
	// This collector NO LONGER exports high-cardinality IP-level metrics
	// It only tracks connection counts and BPF map utilization
	if cfg.ConnectionTracking {
		logger.Info("Starting connection collector (map utilization tracking only)...")
		connectionCollector := collector.NewConnectionCollector(
			bpfManager,
			logger,
			metricsServer.Registry(),
		)

		// Configure connection collector
		if cfg.ConnectionAggregationInterval > 0 {
			connectionCollector.SetAggregationInterval(cfg.ConnectionAggregationInterval)
		}

		// Start connection collection loop
		go connectionCollector.Start(ctx)

		// Start overflow handler for ringbuffer monitoring
		if err := connectionCollector.StartOverflowHandler(ctx); err != nil {
			logger.Warn("Failed to start overflow handler", zap.Error(err))
		}

		logger.Info("Connection tracking enabled (LRU auto-eviction only, no manual cleanup)",
			zap.Duration("aggregation_interval", cfg.ConnectionAggregationInterval))
	} else {
		logger.Info("Connection tracking disabled")
	}

	// Log startup complete
	logger.Info("KubeAdapt eBPF Agent started successfully")
	logger.Info("Metrics available",
		zap.String("url", fmt.Sprintf("http://localhost:%d/metrics", cfg.MetricsPort)))

	// Wait for shutdown signal
	select {
	case sig := <-sigChan:
		logger.Info("Received signal, shutting down...", zap.String("signal", sig.String()))
	case <-ctx.Done():
		logger.Info("Context cancelled, shutting down...")
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Stop metrics server
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error shutting down metrics server", zap.Error(err))
	}

	logger.Info("KubeAdapt eBPF Agent shutdown complete")
}

// checkKernelCompatibility verifies the kernel supports required eBPF features
func checkKernelCompatibility() error {
	// Simple kernel version check by reading /proc/version
	versionData, err := os.ReadFile("/proc/version")
	if err != nil {
		// Not a fatal error - might be running on non-Linux or in container without /proc
		fmt.Println("Warning: Could not read kernel version from /proc/version")
	} else {
		fmt.Printf("Kernel version: %s\n", string(versionData))
	}

	// Check for BPF filesystem
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}

	// Check for tracing
	if _, err := os.Stat("/sys/kernel/debug/tracing"); os.IsNotExist(err) {
		fmt.Println("Warning: Tracing not available at /sys/kernel/debug/tracing")
	}

	return nil
}
