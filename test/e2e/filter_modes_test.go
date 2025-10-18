package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/kubeadapt/ebpf-agent/test/e2e/helpers"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// TestE2EFilterModes validates all filter modes with coordinated deployment and cardinality comparison
// Architecture: Deploy each mode ONCE, measure cardinality, then compare (NO redeployment for comparison!)
// This eliminates wasteful duplicate deployments: 3 deployments total (vs 6 in old architecture)
//
// Filter modes tested:
//   - strict: Track only hostNetwork:false pods
//   - default: Track all K8s pods (hostNetwork:true + false), filter host processes
//   - disabled: Track everything (debug mode)
//
// Verifies cardinality ordering: strict < default < disabled
func TestE2EFilterModes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping filter mode tests in short mode")
	}

	const (
		testNamespace = "test"
		prometheusURL = "http://localhost:30090"
		metricName    = "kubeadapt_connection_traffic_bytes"
	)

	// Shared state: cardinality measurements collected during each mode test
	// Closure allows comparison without redeployment
	cardinalities := make(map[string]float64)

	filterModesFeature := features.New("Filter Modes with Cardinality Comparison").
		Assess("test all filter modes and compare cardinality", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			t.Log("📊 Starting Unified Filter Mode Tests with Cardinality Comparison")
			t.Log("Expected: strict < default < disabled")
			t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

			dm, err := helpers.NewDeploymentManager(cfg)
			if err != nil {
				t.Fatalf("Failed to create deployment manager: %v", err)
			}

			promClient := helpers.NewPrometheusClient(t, prometheusURL)
			trafficGen := helpers.NewTrafficGenerator(t, cfg.Client().RESTConfig())
			podHelper, err := helpers.NewPodHelper(cfg)
			if err != nil {
				t.Fatalf("Failed to create pod helper: %v", err)
			}

			// Filter modes to test in order
			filterModes := []string{"strict", "default", "disabled"}

			// Test each filter mode
			for _, mode := range filterModes {
				t.Logf("\n🔄 Testing Filter Mode: %s", mode)
				t.Log("─────────────────────────────────────────────────────")

				// 1. Cleanup previous deployments
				t.Log("🧹 Cleaning up previous deployments...")
				if err := dm.DeleteAgent(ctx); err != nil {
					t.Logf("Warning: Agent cleanup failed: %v", err)
				}
				if err := dm.DeletePrometheus(ctx); err != nil {
					t.Logf("Warning: Prometheus cleanup failed: %v", err)
				}
				time.Sleep(15 * time.Second) // Increased from 5s for complete cleanup

				// 2. Deploy fresh Prometheus + Agent with specific filter mode
				t.Log("🚀 Deploying fresh Prometheus...")
				if err := dm.DeployPrometheus(ctx); err != nil {
					t.Fatalf("Failed to deploy Prometheus for mode %s: %v", mode, err)
				}

				t.Logf("🤖 Deploying Agent with filter mode: %s", mode)
				if err := dm.DeployAgentWithFilterMode(ctx, mode); err != nil {
					t.Fatalf("Failed to deploy Agent for mode %s: %v", mode, err)
				}

				// 3. Wait for Prometheus to be ready
				if err := promClient.WaitForReady(ctx); err != nil {
					t.Fatalf("Prometheus not ready for mode %s: %v", mode, err)
				}

				// 4. Wait for test pods to be ready
				t.Log("⏳ Waiting for test pods to be ready...")
				if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-a", 2*time.Minute); err != nil {
					t.Fatalf("Pod test-pod-a not ready: %v", err)
				}
				if err := podHelper.WaitForReady(ctx, t, testNamespace, "test-pod-b", 2*time.Minute); err != nil {
					t.Fatalf("Pod test-pod-b not ready: %v", err)
				}

				// 5. Generate identical traffic for all modes
				t.Log("📡 Generating test traffic...")
				if err := trafficGen.GenerateHTTPTraffic(ctx, testNamespace, "test-pod-a", "test-service-b", 50); err != nil {
					t.Fatalf("Failed to generate traffic for mode %s: %v", mode, err)
				}

				// 6. Wait for metrics to be exported and scraped
				t.Log("⏱️  Waiting for metrics export (45 seconds)...")
				time.Sleep(45 * time.Second)

				// 7. Verify traffic is tracked
				t.Log("✅ Verifying traffic is tracked...")
				err = promClient.WaitForMetric(ctx,
					"kubeadapt_connection_traffic_bytes",
					map[string]string{
						"protocol":  "tcp",
						"direction": "egress",
					},
					1.0,
				)
				if err != nil {
					t.Fatalf("Traffic not tracked in %s mode: %v", mode, err)
				}

				// 8. Measure cardinality
				t.Log("📈 Measuring metric cardinality...")
				cardinality, err := promClient.GetMetricCardinality(ctx, metricName)
				if err != nil {
					t.Fatalf("Failed to get cardinality for mode %s: %v", mode, err)
				}

				cardinalities[mode] = cardinality
				t.Logf("✅ Mode: %s → Cardinality: %.0f time series", mode, cardinality)
			}

			// 9. Final cleanup
			t.Log("\n🧹 Final cleanup...")
			if err := dm.DeleteAgent(ctx); err != nil {
				t.Logf("Warning: Final agent cleanup failed: %v", err)
			}
			if err := dm.DeletePrometheus(ctx); err != nil {
				t.Logf("Warning: Final Prometheus cleanup failed: %v", err)
			}

			// 10. Compare cardinalities (NO redeployment needed!)
			t.Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			t.Log("📊 Cardinality Comparison Results:")
			t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			for _, mode := range filterModes {
				t.Logf("  %-10s: %.0f time series", mode, cardinalities[mode])
			}
			t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

			// Verify ordering: strict < default < disabled
			if cardinalities["strict"] >= cardinalities["default"] {
				t.Errorf("❌ Cardinality ordering violation: strict (%.0f) should be < default (%.0f)",
					cardinalities["strict"], cardinalities["default"])
			} else {
				t.Logf("✅ Verified: strict (%.0f) < default (%.0f)",
					cardinalities["strict"], cardinalities["default"])
			}

			if cardinalities["default"] >= cardinalities["disabled"] {
				t.Errorf("❌ Cardinality ordering violation: default (%.0f) should be < disabled (%.0f)",
					cardinalities["default"], cardinalities["disabled"])
			} else {
				t.Logf("✅ Verified: default (%.0f) < disabled (%.0f)",
					cardinalities["default"], cardinalities["disabled"])
			}

			t.Log("\n✅ Filter mode tests complete!")
			t.Logf("Total deployments: 3 (one per mode) - NO redeployment for comparison!")
			t.Log("Old architecture would have required 6 deployments (each mode tested twice)")
			return ctx
		}).
		Feature()

	testCluster.TestEnv().Test(t, filterModesFeature)
}
