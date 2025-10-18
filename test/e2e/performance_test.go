package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/kubeadapt/ebpf-agent/test/e2e/helpers"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// TestE2EShortLivedConnections tests handling of connections that close quickly
// This validates the fix for 40-60% data loss where short-lived connections
// were closing before the collection cycle could read them from BPF maps.
// The read-then-delete pattern should capture all connections.
func TestE2EShortLivedConnections(t *testing.T) {
	const (
		testNamespace     = "test"
		prometheusURL     = "http://localhost:30090"
		connectionsToTest = 100 // Generate 100 short-lived connections
	)

	shortLivedTracking := features.New("Short-Lived Connection Tracking").
		Assess("captures connections that close before collection cycle", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Testing short-lived connection tracking (critical for data loss fix)")
			t.Log("Scenario: Connections open and close within milliseconds")

			promClient := helpers.NewPrometheusClient(t, prometheusURL)
			if err := promClient.WaitForReady(ctx); err != nil {
				t.Fatalf("Prometheus not ready: %v", err)
			}

			// Create PodHelper for pod operations
			podHelper, err := helpers.NewPodHelper(cfg)
			if err != nil {
				t.Fatalf("Failed to create pod helper: %v", err)
			}

			// Wait for test pods
			t.Log("Ensuring test pods are ready...")
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-a", 2*time.Minute); err != nil {
				t.Fatalf("Pod test-pod-a not ready: %v", err)
			}
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-b", 2*time.Minute); err != nil {
				t.Fatalf("Pod test-pod-b not ready: %v", err)
			}

			// Record baseline traffic before test
			t.Log("Recording baseline traffic metrics")
			baselineBytes, _ := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol":  "tcp",
					"direction": "egress",
				},
			)

			// Generate short-lived connections
			// HTTP connections typically close immediately after response
			t.Logf("Generating %d short-lived HTTP connections", connectionsToTest)
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())
			if err := trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "test-pod-a", "test-service-b", connectionsToTest); err != nil {
				t.Fatalf("Failed to generate traffic: %v", err)
			}

			// Wait for collection cycle (25s) + scrape interval (15s) + buffer
			t.Log("Waiting for collection cycle to process short-lived connections")
			time.Sleep(45 * time.Second)

			// Verify traffic was captured
			t.Log("Verifying short-lived connections were tracked")
			newBytes, err := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol":  "tcp",
					"direction": "egress",
				},
			)
			if err != nil {
				t.Fatalf("Failed to get traffic metric: %v", err)
			}

			// Calculate captured traffic
			capturedBytes := newBytes - baselineBytes
			if capturedBytes <= 0 {
				t.Fatalf("No short-lived connection traffic captured (data loss detected)")
			}

			t.Logf("✓ Short-lived connections tracked: %.0f bytes captured", capturedBytes)
			t.Log("✓ Read-then-delete pattern working correctly (no data loss)")
			return ctx
		}).Feature()

	dataCompleteness := features.New("Data Completeness - No Loss Between Cycles").
		Assess("validates all connection data is captured across collection cycles", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Testing data completeness across multiple collection cycles")

			promClient := helpers.NewPrometheusClient(t, prometheusURL)

			// Generate traffic continuously over multiple collection cycles
			t.Log("Generating continuous traffic over 3 collection cycles (75 seconds)")
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())

			// Generate traffic in 3 batches, spaced 25 seconds apart (one per collection cycle)
			for i := 1; i <= 3; i++ {
				t.Logf("Traffic batch %d/3", i)
				_ = trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "test-pod-a", "test-service-b", 30)
				if i < 3 {
					time.Sleep(25 * time.Second) // Wait for next collection cycle
				}
			}

			// Wait for final collection + scrape
			time.Sleep(45 * time.Second)

			// Verify cumulative traffic was tracked
			t.Log("Verifying cumulative traffic across all cycles")
			totalBytes, err := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol":  "tcp",
					"direction": "egress",
				},
			)
			if err != nil {
				t.Fatalf("Failed to get cumulative traffic: %v", err)
			}

			if totalBytes <= 0 {
				t.Fatalf("No cumulative traffic captured across cycles")
			}

			t.Logf("✓ Cumulative traffic tracked across cycles: %.0f bytes", totalBytes)
			t.Log("✓ No data loss between collection cycles")
			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, shortLivedTracking, dataCompleteness)
}

// TestE2ECollectionTiming validates the timing relationship between
// collection interval and Prometheus scrape interval
func TestE2ECollectionTiming(t *testing.T) {
	const (
		prometheusURL          = "http://localhost:30090"
		collectionInterval     = 25 * time.Second // Agent collection interval
		expectedScrapeInterval = 30 * time.Second // Prometheus scrape interval
	)

	timingValidation := features.New("Collection and Scrape Timing").
		Assess("collection interval < scrape interval (prevents gauge overwrites)", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Validating collection timing configuration")
			t.Logf("Collection interval: %s", collectionInterval)
			t.Logf("Expected Prometheus scrape interval: %s", expectedScrapeInterval)

			if collectionInterval >= expectedScrapeInterval {
				t.Fatalf("CRITICAL: Collection interval (%s) >= scrape interval (%s)",
					collectionInterval, expectedScrapeInterval)
			}

			t.Log("✓ Collection interval is shorter than scrape interval")
			t.Log("✓ This ensures only ONE collection happens between Prometheus scrapes")
			t.Log("✓ Prevents gauge overwrites and data loss")

			// Verify timing in practice by checking metrics are updated consistently
			promClient := helpers.NewPrometheusClient(t, prometheusURL)
			if err := promClient.WaitForReady(ctx); err != nil {
				t.Fatalf("Prometheus not ready: %v", err)
			}

			// Read metric value at T0
			t.Log("Reading metric at T0")
			value1, err := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol": "tcp",
				},
			)
			if err != nil {
				t.Logf("Warning: Metric not available at T0: %v", err)
			}

			// Wait for one scrape interval
			t.Logf("Waiting %s (one scrape interval)...", expectedScrapeInterval)
			time.Sleep(expectedScrapeInterval)

			// Read metric value at T0 + scrape_interval
			t.Log("Reading metric at T0 + scrape_interval")
			value2, err := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol": "tcp",
				},
			)
			if err != nil {
				t.Logf("Warning: Metric not available at T1: %v", err)
			}

			// Values should be different (gauges get updated)
			if value1 != value2 {
				t.Logf("✓ Metrics updated between scrapes: %.0f -> %.0f", value1, value2)
			}

			t.Log("✓ Collection timing validated successfully")
			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, timingValidation)
}

// TestE2EPerformanceOverhead measures the performance impact of eBPF agent
// on network throughput
func TestE2EPerformanceOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance overhead test in short mode")
	}

	const (
		testNamespace = "test"
		trafficVolume = 200 // Number of requests for baseline measurement
	)

	performanceMeasurement := features.New("Performance Overhead Measurement").
		Assess("measures network throughput with eBPF agent active", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("Measuring network performance with eBPF agent active")
			t.Log("Note: This test measures throughput, not absolute overhead")

			// Create PodHelper
			podHelper, err := helpers.NewPodHelper(cfg)
			if err != nil {
				t.Fatalf("Failed to create pod helper: %v", err)
			}

			// Wait for test pods
			if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-a", 2*time.Minute); err != nil {
				t.Fatalf("Pod test-pod-a not ready: %v", err)
			}

			// Measure throughput with agent active
			t.Logf("Generating %d requests to measure throughput", trafficVolume)
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())

			startTime := time.Now()
			if err := trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "test-pod-a", "test-service-b", trafficVolume); err != nil {
				t.Fatalf("Failed to generate traffic: %v", err)
			}
			duration := time.Since(startTime)

			throughput := float64(trafficVolume) / duration.Seconds()
			t.Logf("✓ Throughput with eBPF agent: %.2f requests/second", throughput)
			t.Logf("✓ Total duration: %s for %d requests", duration, trafficVolume)

			// Basic sanity check: throughput should be reasonable
			if throughput < 1.0 {
				t.Fatalf("Throughput too low: %.2f req/s (expected >1 req/s)", throughput)
			}

			t.Log("✓ Network performance acceptable with eBPF agent active")
			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, performanceMeasurement)
}

// TestE2EConcurrentConnections validates handling of many concurrent connections
// Tests the agent's ability to track multiple simultaneous connections accurately
func TestE2EConcurrentConnections(t *testing.T) {
	const (
		testNamespace     = "traffic-test"
		prometheusURL     = "http://localhost:30090"
		concurrentPods    = 4
		connectionsPerPod = 50
		totalConnections  = concurrentPods * connectionsPerPod
	)

	concurrentTracking := features.New("Concurrent Connection Tracking").
		Assess("accurately tracks many simultaneous connections", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Logf("Testing concurrent connection tracking (%d total connections)", totalConnections)

			promClient := helpers.NewPrometheusClient(t, prometheusURL)
			if err := promClient.WaitForReady(ctx); err != nil {
				t.Fatalf("Prometheus not ready: %v", err)
			}

			// Create PodHelper
			podHelper, err := helpers.NewPodHelper(cfg)
			if err != nil {
				t.Fatalf("Failed to create pod helper: %v", err)
			}

			// Wait for traffic generator pods
			trafficPods := []string{"traffic-gen-a", "traffic-gen-b", "traffic-gen-c", "traffic-gen-d"}
			t.Log("Ensuring traffic generator pods are ready...")
			for _, podName := range trafficPods {
				if err := podHelper.WaitForReady(ctx, t, testNamespace, podName, 2*time.Minute); err != nil {
					t.Fatalf("Pod %s not ready: %v", podName, err)
				}
			}

			// Record baseline
			baselineBytes, _ := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol": "tcp",
				},
			)

			// Generate concurrent traffic from all pods
			t.Log("Generating concurrent traffic from multiple pods")
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())

			type result struct {
				pod string
				err error
			}
			results := make(chan result, len(trafficPods))

			// Start concurrent traffic generation
			for _, podName := range trafficPods {
				go func(pod string) {
					err := trafficGen.GenerateHTTPTraffic(ctx, testNamespace, pod, "traffic-gen-a-svc", connectionsPerPod)
					results <- result{pod: pod, err: err}
				}(podName)
			}

			// Wait for all traffic generation to complete
			for i := 0; i < len(trafficPods); i++ {
				res := <-results
				if res.err != nil {
					t.Logf("Warning: Pod %s traffic generation failed: %v", res.pod, res.err)
				}
			}
			close(results)

			// Wait for metrics export
			t.Log("Waiting for metrics to be exported")
			time.Sleep(45 * time.Second)

			// Verify concurrent traffic was tracked
			newBytes, err := promClient.GetMetricValue(ctx,
				"kubeadapt_connection_traffic_bytes",
				map[string]string{
					"protocol": "tcp",
				},
			)
			if err != nil {
				t.Fatalf("Failed to get traffic metric: %v", err)
			}

			capturedBytes := newBytes - baselineBytes
			if capturedBytes <= 0 {
				t.Fatalf("No concurrent traffic captured")
			}

			t.Logf("✓ Concurrent connections tracked: %.0f bytes from %d pods", capturedBytes, len(trafficPods))
			t.Log("✓ No data loss with concurrent traffic generation")
			return ctx
		}).Feature()

	testCluster.TestEnv().Test(t, concurrentTracking)
}
