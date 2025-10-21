package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Import pprof for profiling endpoints
	"os"
	"os/signal"
	"strings"
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
	if err := checkKernelCompatibility(logger); err != nil {
		logger.Fatal("Kernel compatibility check failed", zap.Error(err))
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// ═══════════════════════════════════════════════════════════════
	// CRITICAL: Start metrics server BEFORE BPF loading
	// This ensures metrics are scrapable even if BPF load fails
	// ═══════════════════════════════════════════════════════════════
	metricsServer := metrics.NewServer(cfg.MetricsPort, logger)
	go func() {
		if err := metricsServer.Start(); err != nil {
			logger.Error("Metrics server error", zap.Error(err))
		}
	}()

	// Give metrics server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Initialize BPF manager
	bpfManager, err := bpf.NewManager(logger)
	if err != nil {
		// Don't use Fatal - keep metrics server alive for observability
		logger.Error("Failed to initialize BPF manager", zap.Error(err))
		metricsServer.ReportBPFLoadFailure(err, 0)
		// Wait for signal to keep pod alive (easier debugging)
		<-sigChan
		return
	}
	defer func() {
		logger.Info("Cleaning up BPF programs...")
		if err := bpfManager.Close(); err != nil {
			logger.Error("Error closing BPF manager", zap.Error(err))
		}
	}()

	// Load and attach BPF programs with timing
	bpfLoadStart := time.Now()
	if err := bpfManager.LoadAndAttach(cfg.NetnsFilterMode); err != nil {
		bpfLoadDuration := time.Since(bpfLoadStart)
		// Don't use Fatal - keep metrics server alive for observability
		logger.Error("Failed to load BPF programs",
			zap.Error(err),
			zap.Duration("duration", bpfLoadDuration))
		metricsServer.ReportBPFLoadFailure(err, bpfLoadDuration)
		// Pod stays alive (not ready) for debugging. Metrics/health endpoints remain scrapable.
		// To retry: delete the pod, DaemonSet will create a new one.
		logger.Info("Pod will stay alive for debugging. Check /metrics and /health endpoints.")
		<-sigChan
		return
	}
	bpfLoadDuration := time.Since(bpfLoadStart)
	metricsServer.ReportBPFLoadSuccess(bpfLoadDuration)
	logger.Info("BPF programs loaded and attached successfully",
		zap.String("netns_filter_mode", cfg.NetnsFilterMode),
		zap.Duration("duration", bpfLoadDuration))

	// NOTE: Container discovery and cache removed
	// Pod-level metrics are sufficient since K8s pods share network namespace
	// Backend handles all metadata enrichment (pod names, namespaces, services)

	// Initialize profiling server if enabled
	if cfg.EnableProfiling {
		logger.Info("Starting profiling server (pprof)",
			zap.Int("port", cfg.ProfilingPort),
			zap.String("endpoints", fmt.Sprintf("http://localhost:%d/debug/pprof/", cfg.ProfilingPort)))
		go func() {
			// Create a new HTTP server for pprof
			pprofServer := &http.Server{
				Addr:         fmt.Sprintf(":%d", cfg.ProfilingPort),
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			if err := pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("Profiling server error", zap.Error(err))
			}
		}()
	}

	// NOTE: BPF map dumping moved to collector (synchronized with collection cycle)
	// When cfg.DumpBPFMaps is enabled, collector dumps maps before deletion
	// This ensures perfect synchronization with read-then-delete pattern

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
		connectionCollector := collector.NewConnectionCollector(
			bpfManager,
			logger,
			metricsServer.Registry(),
			cfg, // Pass config for DumpBPFMaps flag
		)

		// Configure connection collector
		if cfg.CollectionInterval > 0 {
			connectionCollector.SetAggregationInterval(cfg.CollectionInterval)
		}

		// Start connection collection loop
		go connectionCollector.Start(ctx)

		// Start overflow handler for ringbuffer monitoring
		if err := connectionCollector.StartOverflowHandler(ctx); err != nil {
			logger.Warn("Failed to start overflow handler", zap.Error(err))
		}

		// Warn if debug logging is enabled - high overflow rates may block ring buffer reader
		if logger.Level() == zap.DebugLevel {
			logger.Warn("Debug logging is enabled with connection tracking - " +
				"high overflow rates may block ring buffer reader. " +
				"Consider using INFO level in production.")
		}

		logger.Info("Connection tracking enabled (read-then-delete pattern with overflow ringbuffer)",
			zap.Duration("collection_interval", cfg.CollectionInterval))
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
func checkKernelCompatibility(logger *zap.Logger) error {
	// Simple kernel version check by reading /proc/version
	versionData, err := os.ReadFile("/proc/version")
	if err != nil {
		// Not a fatal error - might be running on non-Linux or in container without /proc
		logger.Warn("Could not read kernel version from /proc/version",
			zap.Error(err))
	} else {
		// Log kernel version for debugging and support purposes
		kernelVersion := strings.TrimSpace(string(versionData))
		logger.Info("Detected kernel version", zap.String("version", kernelVersion))
	}

	// Check for BPF filesystem
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}
	logger.Debug("BPF filesystem available", zap.String("path", "/sys/fs/bpf"))

	// Check for tracing
	if _, err := os.Stat("/sys/kernel/debug/tracing"); os.IsNotExist(err) {
		logger.Warn("Tracing not available at /sys/kernel/debug/tracing",
			zap.String("note", "Some debugging features may not work"))
	} else {
		logger.Debug("Tracing filesystem available", zap.String("path", "/sys/kernel/debug/tracing"))
	}

	return nil
}
