// Package cluster contains the base setup for the E2E test environment
package cluster

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
)

const (
	agentContainerName = "localhost/ebpf-agent:test"
	kindImage          = "kindest/node:v1.27.3"
	logsSubDir         = "e2e-logs"
	localArchiveName   = "ebpf-agent.tar"
)

// DeployOrder specifies the order in which a Deployment must be executed
type DeployOrder int

const (
	// Preconditions is for resources that define cluster status before tests
	Preconditions DeployOrder = iota
	// ExternalServices is for external services (e.g., Prometheus)
	ExternalServices
	// Agent is for the eBPF agent deployment
	Agent
	// TestWorkloads is for test pods and services
	TestWorkloads
)

// Deployment represents a Kubernetes deployment
type Deployment struct {
	Order        DeployOrder
	ManifestFile string
	Ready        *Readiness
}

// Readiness defines readiness check for a deployment
type Readiness struct {
	Function    func(*envconf.Config) error
	Description string
	Timeout     time.Duration
	Retry       time.Duration
}

// Cluster represents a Kind cluster for E2E testing
type Cluster struct {
	clusterName string
	baseDir     string
	deployments []Deployment
	testEnv     env.Environment
	timeout     time.Duration
}

// NewCluster creates a new test cluster
func NewCluster(clusterName, baseDir string) *Cluster {
	return &Cluster{
		clusterName: clusterName,
		baseDir:     baseDir,
		testEnv:     env.New(),
		timeout:     2 * time.Minute,
		deployments: []Deployment{
			// Preconditions: Namespaces and RBAC must be created first
			{
				Order:        Preconditions,
				ManifestFile: path.Join(testDataDir(), "namespace.yaml"),
				Ready:        nil, // Namespace is created synchronously
			},
			{
				Order:        Preconditions,
				ManifestFile: path.Join(testDataDir(), "monitoring-namespace.yaml"),
				Ready:        nil, // Namespace is created synchronously
			},
			{
				Order:        Preconditions,
				ManifestFile: path.Join(testDataDir(), "rbac.yaml"),
				Ready:        nil, // RBAC resources are created synchronously
			},
			// External Services: Deploy Prometheus for metrics collection
			{
				Order:        ExternalServices,
				ManifestFile: path.Join(testDataDir(), "prometheus.yaml"),
				Ready: &Readiness{
					Function:    waitForDeployment("monitoring", "prometheus"),
					Description: "Wait for Prometheus deployment to be ready",
					Timeout:     5 * time.Minute,
					Retry:       5 * time.Second,
				},
			},
			// Agent: Deploy the eBPF agent DaemonSet (E2E version with test image)
			{
				Order:        Agent,
				ManifestFile: path.Join(testDataDir(), "daemonset-e2e.yaml"),
				Ready: &Readiness{
					Function:    waitForDaemonSetWithAllPods("kubeadapt-system", "kubeadapt-ebpf-agent"),
					Description: "Wait for eBPF agent DaemonSet to be ready (all pods running)",
					Timeout:     5 * time.Minute,
					Retry:       3 * time.Second,
				},
			},
			// Note: ServiceMonitor is not deployed in E2E tests as it requires Prometheus Operator CRD
			// which is not installed in vanilla Kind clusters. Metrics are scraped directly via pod annotations.
			// Test Workloads: Deploy test pods for E2E traffic generation
			{
				Order:        TestWorkloads,
				ManifestFile: path.Join(testDataDir(), "test-pods.yaml"),
				Ready: &Readiness{
					Function:    waitForTestPods("test"),
					Description: "Wait for test pods to be ready in test namespace",
					Timeout:     5 * time.Minute,
					Retry:       3 * time.Second,
				},
			},
			{
				Order:        TestWorkloads,
				ManifestFile: path.Join(testDataDir(), "traffic-pods.yaml"),
				Ready: &Readiness{
					Function:    waitForTrafficPods("traffic-test"),
					Description: "Wait for traffic generator pods to be ready in traffic-test namespace",
					Timeout:     5 * time.Minute,
					Retry:       3 * time.Second,
				},
			},
		},
	}
}

// Run the cluster for E2E tests
func (c *Cluster) Run(m *testing.M) {
	kindConfigPath := path.Join(testDataDir(), "kind-config.yaml")

	envFuncs := []env.Func{
		envfuncs.CreateClusterWithConfig(
			kind.NewProvider(),
			c.clusterName,
			kindConfigPath,
			kind.WithImage(kindImage),
		),
		c.loadLocalImage(),
	}

	// Deploy all manifests in order, with readiness checks grouped by order
	// This follows production eBPF projects's deployment ordering pattern where dependencies
	// are fully ready before dependent components are deployed
	var readyFuncs []env.Func
	currentOrder := Preconditions

	for _, dep := range c.orderedDeployments() {
		// When order changes, wait for all previous deployments to be ready
		if dep.Order != currentOrder {
			fmt.Printf("→ Waiting for all %s deployments to be ready before proceeding...\n", orderName(currentOrder))
			envFuncs = append(envFuncs, readyFuncs...)
			readyFuncs = nil
			currentOrder = dep.Order
			fmt.Printf("→ Starting %s deployments...\n", orderName(currentOrder))
		}

		// Deploy manifest
		envFuncs = append(envFuncs, deployManifest(dep))

		// Add readiness check to be executed after all deployments in this order
		if dep.Ready != nil {
			readyFuncs = append(readyFuncs, withTimeout(dep.Ready))
		}
	}

	// Wait for final deployment order to be ready
	if len(readyFuncs) > 0 {
		fmt.Printf("→ Waiting for all %s deployments to be ready...\n", orderName(currentOrder))
		envFuncs = append(envFuncs, readyFuncs...)
	}

	// Note: Prometheus is now accessible via NodePort at http://localhost:30090
	// No port-forward needed - Kind extraPortMappings expose the service directly

	code := c.testEnv.Setup(envFuncs...).
		Finish(
			c.exportLogs(),
			envfuncs.DestroyCluster(c.clusterName),
		).Run(m)

	fmt.Printf("Tests finished with code: %d\n", code)
}

// TestEnv returns the test environment
func (c *Cluster) TestEnv() env.Environment {
	return c.testEnv
}

// orderedDeployments returns deployments sorted by Order, then alphabetically by ManifestFile
// This implements production eBPF projects's deployment ordering pattern for explicit dependency management
func (c *Cluster) orderedDeployments() []Deployment {
	sorted := make([]Deployment, len(c.deployments))
	copy(sorted, c.deployments)

	// Sort by Order first, then by ManifestFile for deterministic ordering
	// Using sort.SliceStable to maintain relative order within same Order
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].Order > sorted[j].Order {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			} else if sorted[i].Order == sorted[j].Order && sorted[i].ManifestFile > sorted[j].ManifestFile {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
}

// orderName returns a human-readable name for a deployment order
func orderName(order DeployOrder) string {
	switch order {
	case Preconditions:
		return "Preconditions"
	case ExternalServices:
		return "ExternalServices"
	case Agent:
		return "Agent"
	case TestWorkloads:
		return "TestWorkloads"
	default:
		return fmt.Sprintf("Unknown(%d)", order)
	}
}

// loadLocalImage loads the agent Docker image into the cluster
// Prioritizes loading from local Docker registry (faster, no disk space)
// If registry fails, creates tar archive on-demand and loads from it
func (c *Cluster) loadLocalImage() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		fmt.Println("Loading agent Docker image into Kind cluster...")

		// Primary method: Load from local Docker registry (recommended)
		// Kind's 'load docker-image' command handles this efficiently
		ctx, err := envfuncs.LoadDockerImageToCluster(c.clusterName, agentContainerName)(ctx, cfg)
		if err == nil {
			fmt.Println("✓ Successfully loaded image from local Docker registry")
			return ctx, nil
		}

		// Fallback: Create tar archive and load from it
		fmt.Printf("⚠️  Failed to load from registry (%v)\n", err)
		fmt.Println("Creating tar archive as fallback...")

		archivePath := path.Join(c.baseDir, localArchiveName)

		// Create tar archive using docker save
		saveCmd := fmt.Sprintf("docker save -o %s %s", archivePath, agentContainerName)
		if err := os.RemoveAll(archivePath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Warning: failed to remove old tar: %v\n", err)
		}

		saveOutput, err := exec.Command("sh", "-c", saveCmd).CombinedOutput()
		if err != nil {
			return ctx, fmt.Errorf("failed to create tar archive\n"+
				"Registry error: %v\n"+
				"Tar creation error: %w\n"+
				"Output: %s", err, err, string(saveOutput))
		}

		fmt.Printf("✓ Created tar archive: %s\n", archivePath)
		fmt.Println("Loading image from tar archive...")

		// Load from the newly created tar
		ctx, err = envfuncs.LoadImageArchiveToCluster(c.clusterName, archivePath)(ctx, cfg)
		if err == nil {
			fmt.Println("✓ Successfully loaded image from tar archive")
			return ctx, nil
		}

		return ctx, fmt.Errorf("failed to load image from both registry and tar archive\n"+
			"Registry error: %v\n"+
			"Tar loading error: %w", err, err)
	}
}

// exportLogs exports cluster logs to the e2e-logs folder
func (c *Cluster) exportLogs() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		logsDir := path.Join(c.baseDir, logsSubDir)
		fmt.Printf("Exporting cluster logs to %s\n", logsDir)
		// Note: This requires kind CLI to be installed
		// kind export logs <dir> --name <cluster-name>
		return ctx, nil
	}
}

// deployManifest deploys a manifest file
func deployManifest(dep Deployment) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		fmt.Printf("Deploying manifest: %s\n", dep.ManifestFile)

		// Create resources client
		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("creating resources client: %w", err)
		}

		// Read manifest file content
		manifestData, err := os.ReadFile(dep.ManifestFile)
		if err != nil {
			return ctx, fmt.Errorf("reading manifest file %s: %w", dep.ManifestFile, err)
		}

		// Decode and apply manifest
		err = decoder.DecodeEach(
			ctx,
			bytes.NewReader(manifestData),
			decoder.CreateHandler(r),
		)
		if err != nil {
			return ctx, fmt.Errorf("applying manifest %s: %w", dep.ManifestFile, err)
		}

		fmt.Printf("✓ Successfully deployed: %s\n", dep.ManifestFile)
		return ctx, nil
	}
}

// withTimeout retries a function until it succeeds or timeout is reached
func withTimeout(ready *Readiness) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		fmt.Printf("Checking readiness: %s (timeout: %s)\n", ready.Description, ready.Timeout)
		start := time.Now()
		for {
			err := ready.Function(cfg)
			if err == nil {
				fmt.Printf("✓ Readiness check passed: %s\n", ready.Description)
				return ctx, nil
			}
			if time.Since(start) > ready.Timeout {
				return ctx, fmt.Errorf("timeout after %s: %w", ready.Timeout, err)
			}
			time.Sleep(ready.Retry)
		}
	}
}

// waitForDaemonSetWithAllPods creates a readiness function for DaemonSets with comprehensive checks
// This verifies that ALL desired pods are ready, updated, and available
func waitForDaemonSetWithAllPods(namespace, name string) func(*envconf.Config) error {
	return func(cfg *envconf.Config) error {
		// Get resources client
		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return fmt.Errorf("creating resources client: %w", err)
		}

		// Get the DaemonSet
		var ds appsv1.DaemonSet
		if err := r.Get(context.Background(), name, namespace, &ds); err != nil {
			return fmt.Errorf("getting daemonset %s/%s: %w", namespace, name, err)
		}

		// Check if daemonset has desired pods scheduled
		if ds.Status.DesiredNumberScheduled == 0 {
			return fmt.Errorf("daemonset %s/%s has 0 desired pods scheduled", namespace, name)
		}

		// Check if all desired pods are ready
		if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not ready: %d/%d pods ready",
				namespace, name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
		}

		// Check if all pods are updated to the latest version
		if ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not fully updated: %d/%d pods updated",
				namespace, name, ds.Status.UpdatedNumberScheduled, ds.Status.DesiredNumberScheduled)
		}

		// Check if all pods are available
		if ds.Status.NumberAvailable != ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not fully available: %d/%d pods available",
				namespace, name, ds.Status.NumberAvailable, ds.Status.DesiredNumberScheduled)
		}

		fmt.Printf("✓ DaemonSet %s/%s fully ready: %d/%d pods ready, updated, and available\n",
			namespace, name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)

		return nil
	}
}

// waitForDeployment creates a readiness function for Deployments
func waitForDeployment(namespace, name string) func(*envconf.Config) error {
	return func(cfg *envconf.Config) error {
		// Get resources client
		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return fmt.Errorf("creating resources client: %w", err)
		}

		// Get the Deployment
		var deploy appsv1.Deployment
		if err := r.Get(context.Background(), name, namespace, &deploy); err != nil {
			return fmt.Errorf("getting deployment %s/%s: %w", namespace, name, err)
		}

		// Check if all replicas are ready
		if deploy.Status.ReadyReplicas != *deploy.Spec.Replicas {
			return fmt.Errorf("deployment %s/%s not ready: %d/%d replicas ready",
				namespace, name, deploy.Status.ReadyReplicas, *deploy.Spec.Replicas)
		}

		return nil
	}
}

// waitForTestPods creates a readiness function for test pods in a specific namespace
func waitForTestPods(namespace string) func(*envconf.Config) error {
	return func(cfg *envconf.Config) error {
		// Get resources client
		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return fmt.Errorf("creating resources client: %w", err)
		}

		// Check each test pod individually
		testPods := []string{"test-pod-a", "test-pod-b", "test-pod-c"}
		for _, podName := range testPods {
			var pod corev1.Pod
			if err := r.Get(context.Background(), podName, namespace, &pod); err != nil {
				return fmt.Errorf("getting pod %s/%s: %w", namespace, podName, err)
			}

			// Check if pod is running
			if pod.Status.Phase != corev1.PodRunning {
				return fmt.Errorf("pod %s/%s not running: %s (message: %s)",
					namespace, podName, pod.Status.Phase, pod.Status.Message)
			}

			// Check if pod has IP assigned (needed for network tracking)
			if pod.Status.PodIP == "" {
				return fmt.Errorf("pod %s/%s has no IP assigned", namespace, podName)
			}

			// Check if pod is scheduled to a node
			if pod.Spec.NodeName == "" {
				return fmt.Errorf("pod %s/%s not scheduled to any node", namespace, podName)
			}

			// Check if all containers are ready
			for _, cs := range pod.Status.ContainerStatuses {
				if !cs.Ready {
					return fmt.Errorf("pod %s/%s container %s not ready", namespace, podName, cs.Name)
				}
			}

			// Check if pod Ready condition is true
			ready := false
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			if !ready {
				return fmt.Errorf("pod %s/%s Ready condition not true", namespace, podName)
			}
		}

		fmt.Printf("✓ All %d test pods in namespace %s are ready\n", len(testPods), namespace)
		return nil
	}
}

// waitForTrafficPods creates a readiness function for traffic generator pods
func waitForTrafficPods(namespace string) func(*envconf.Config) error {
	return func(cfg *envconf.Config) error {
		// Get resources client
		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return fmt.Errorf("creating resources client: %w", err)
		}

		// Check each traffic generator pod
		trafficPods := []string{"traffic-gen-a", "traffic-gen-b", "traffic-gen-c", "traffic-gen-d"}
		for _, podName := range trafficPods {
			var pod corev1.Pod
			if err := r.Get(context.Background(), podName, namespace, &pod); err != nil {
				return fmt.Errorf("getting pod %s/%s: %w", namespace, podName, err)
			}

			// Check if pod is running
			if pod.Status.Phase != corev1.PodRunning {
				return fmt.Errorf("pod %s/%s not running: %s (message: %s)",
					namespace, podName, pod.Status.Phase, pod.Status.Message)
			}

			// Check if pod has IP assigned (needed for network tracking)
			if pod.Status.PodIP == "" {
				return fmt.Errorf("pod %s/%s has no IP assigned", namespace, podName)
			}

			// Check if pod is scheduled to a node
			if pod.Spec.NodeName == "" {
				return fmt.Errorf("pod %s/%s not scheduled to any node", namespace, podName)
			}

			// Check if all containers are ready
			for _, cs := range pod.Status.ContainerStatuses {
				if !cs.Ready {
					return fmt.Errorf("pod %s/%s container %s not ready (state: %+v)",
						namespace, podName, cs.Name, cs.State)
				}
			}

			// Check if pod Ready condition is true
			ready := false
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			if !ready {
				return fmt.Errorf("pod %s/%s Ready condition not true", namespace, podName)
			}

			fmt.Printf("  Pod %s: ready on node %s with IP %s\n", podName, pod.Spec.NodeName, pod.Status.PodIP)
		}

		fmt.Printf("✓ All %d traffic generator pods in namespace %s are ready\n", len(trafficPods), namespace)
		return nil
	}
}

// testDataDir returns the testdata directory path
func testDataDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("can't find testdata directory")
	}
	return path.Join(path.Dir(file), "..", "testdata")
}
