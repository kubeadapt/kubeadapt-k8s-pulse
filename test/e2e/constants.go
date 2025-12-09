package e2e

import "time"

// E2E Test Timing Constants
//
// These constants define test timing for the eBPF agent's metric collection.
//
// Architecture:
// 1. Agent collects metrics from BPF maps every 25 seconds
// 2. Agent exposes metrics on /metrics endpoint
// 3. Prometheus scrapes /metrics every 15 seconds
// 4. Tests need to wait for BOTH collection AND scrape to complete
const (
	// AgentCollectionInterval is how often the agent collects metrics from BPF maps
	// and updates the Prometheus gauges.
	//
	// Location: internal/collector/connection_collector.go (collection ticker)
	AgentCollectionInterval = 25 * time.Second

	// PrometheusScrapeInterval is how often Prometheus scrapes the agent's /metrics endpoint.
	//
	// Configuration: test/e2e/testdata/external-services.yaml (Prometheus config)
	// Note: This is the TEST environment scrape interval. Production may differ.
	PrometheusScrapeInterval = 15 * time.Second

	// MetricsExportBuffer is extra time to account for:
	// - BPF map read latency
	// - Metrics processing time
	// - Network delays
	// - Prometheus query evaluation time
	MetricsExportBuffer = 5 * time.Second

	// MetricsExportWaitTime is the total time to wait for metrics to be:
	// 1. Collected by the agent from BPF maps (25s)
	// 2. Exported to /metrics endpoint
	// 3. Scraped by Prometheus (15s)
	// 4. Available for queries (5s buffer)
	//
	// Total: 25s + 15s + 5s = 45s
	//
	// Use this constant in E2E tests when:
	// - Generating traffic and verifying it appears in Prometheus
	// - Testing metrics accuracy after agent operations
	// - Validating metric collection after configuration changes
	MetricsExportWaitTime = AgentCollectionInterval + PrometheusScrapeInterval + MetricsExportBuffer

	// DaemonCleanupWaitTime is the time to wait for the agent daemon to:
	// - Gracefully shut down connections
	// - Clean up BPF resources
	// - Restart and reinitialize
	//
	// Use this constant when testing:
	// - Agent restarts (filter mode changes, configuration updates)
	// - Resource cleanup behavior
	// - Daemon lifecycle management
	DaemonCleanupWaitTime = 15 * time.Second
)
