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
	"github.com/kubeadapt/ebpf-agent/internal/container"
	"github.com/kubeadapt/ebpf-agent/internal/k8s"
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
	defer logger.Sync()

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

	// Initialize container discovery
	logger.Info("Initializing container discovery...")
	var discoverer container.Discoverer
	switch cfg.ContainerDiscovery {
	case "kubernetes":
		discoverer, err = container.NewKubernetesDiscoverer(cfg.KubernetesNamespace, logger)
	case "proc":
		discoverer, err = container.NewProcDiscoverer("/host/proc", logger)
	default:
		err = fmt.Errorf("unknown container discovery method: %s", cfg.ContainerDiscovery)
	}
	if err != nil {
		logger.Fatal("Failed to initialize container discovery", zap.Error(err))
	}

	// Start container discovery
	containerCache := container.NewCache()
	go func() {
		if err := discoverer.Start(ctx, containerCache); err != nil {
			logger.Error("Container discovery error", zap.Error(err))
		}
	}()

	// Initialize metrics server
	logger.Info("Starting metrics server", zap.Int("port", cfg.MetricsPort))
	metricsServer := metrics.NewServer(cfg.MetricsPort, logger)
	go func() {
		if err := metricsServer.Start(); err != nil {
			logger.Error("Metrics server error", zap.Error(err))
		}
	}()

	// Initialize zone mapper for Kubernetes topology
	// No caching - queries K8s API in real-time for autoscaling clusters
	logger.Info("Initializing Kubernetes zone mapper (real-time queries, no caching)...")
	zoneMapper, err := k8s.NewZoneMapper(logger)
	if err != nil {
		logger.Warn("Failed to initialize zone mapper, continuing without zone information", zap.Error(err))
		// Create a minimal zone mapper that returns "unknown" for all IPs
		zoneMapper = &k8s.ZoneMapper{}
	}

	// Initialize container metrics collector
	logger.Info("Starting metrics collector...")
	metricsCollector := collector.New(
		bpfManager,
		containerCache,
		metricsServer.Registry(),
		collector.Options{
			CollectionInterval: cfg.CollectionInterval,
			BatchSize:         cfg.BatchSize,
		},
		logger,
	)

	// Start container metrics collection loop
	go metricsCollector.Start(ctx)

	// Initialize connection collector for network traffic tracking
	if cfg.ConnectionTracking {
		logger.Info("Starting connection collector...")
		connectionCollector := collector.NewConnectionCollector(
			bpfManager,
			zoneMapper,
			logger,
			metricsServer.Registry(),
		)

		// Configure connection collector
		if cfg.TopFlowsLimit > 0 {
			connectionCollector.SetTopFlowsLimit(cfg.TopFlowsLimit)
		}
		if cfg.ConnectionCleanupInterval > 0 {
			connectionCollector.SetCleanupInterval(cfg.ConnectionCleanupInterval)
		}
		if cfg.ConnectionAggregationInterval > 0 {
			connectionCollector.SetAggregationInterval(cfg.ConnectionAggregationInterval)
		}

		// Start connection collection loop
		go connectionCollector.Start(ctx)

		logger.Info("Connection tracking enabled",
			zap.Int("top_flows_limit", cfg.TopFlowsLimit),
			zap.Duration("cleanup_interval", cfg.ConnectionCleanupInterval),
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
	// Read kernel version
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}

	// Convert kernel release to string (null-terminated)
	releaseBytes := uname.Release[:]
	releaseLen := 0
	for i, b := range releaseBytes {
		if b == 0 {
			releaseLen = i
			break
		}
	}
	release := string(releaseBytes[:releaseLen])

	// Log kernel version using fmt.Printf since we don't have logger here
	fmt.Printf("Kernel version: %s\n", release)

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