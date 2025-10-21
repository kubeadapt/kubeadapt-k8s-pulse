package helpers

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"runtime"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// DeploymentManager handles dynamic Prometheus and Agent deployments for filter mode testing
// This enables coordinated deployment strategy where each test deploys fresh Prometheus + Agent
// with specific filter mode configuration, ensuring clean metrics and proper isolation
type DeploymentManager struct {
	cfg *envconf.Config
	r   *resources.Resources
}

// NewDeploymentManager creates a new deployment manager
func NewDeploymentManager(cfg *envconf.Config) (*DeploymentManager, error) {
	r, err := resources.New(cfg.Client().RESTConfig())
	if err != nil {
		return nil, fmt.Errorf("creating resources client: %w", err)
	}
	return &DeploymentManager{cfg: cfg, r: r}, nil
}

// DeployPrometheus deploys fresh Prometheus instance with clean emptyDir storage
// This ensures each test starts with empty metrics data
func (dm *DeploymentManager) DeployPrometheus(ctx context.Context) error {
	// Read prometheus.yaml from testdata
	manifestPath := path.Join(testDataDir(), "prometheus.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading prometheus manifest: %w", err)
	}

	// Apply manifest - creates ConfigMap, Deployment, Service, ServiceAccount, RBAC
	err = decoder.DecodeEach(ctx, bytes.NewReader(data), decoder.CreateHandler(dm.r))
	if err != nil {
		return fmt.Errorf("applying prometheus manifest: %w", err)
	}

	// Wait for Prometheus deployment to be ready
	return dm.waitForPrometheusReady(ctx, 3*time.Minute)
}

// DeployAgentWithFilterMode deploys Agent DaemonSet with specific EBPF_NETNS_FILTER_MODE
// This patches the base daemonset-e2e.yaml to inject the filter mode environment variable
// and optionally overrides the image tag (from IMAGE_TAG env var) to prevent Docker cache issues
func (dm *DeploymentManager) DeployAgentWithFilterMode(ctx context.Context, filterMode string) error {
	// Read daemonset-e2e.yaml
	manifestPath := path.Join(testDataDir(), "daemonset-e2e.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading daemonset manifest: %w", err)
	}

	// Decode all resources (DaemonSet + Service)
	objs, err := decoder.DecodeAll(ctx, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decoding daemonset manifest: %w", err)
	}

	// Check if IMAGE_TAG env var is set (from Makefile)
	// This allows test-e2e-fast and test-e2e-stress to use timestamped tags
	imageTag := os.Getenv("IMAGE_TAG")
	if imageTag == "" {
		imageTag = "test" // Default fallback
	}
	imageRef := fmt.Sprintf("localhost/ebpf-agent:%s", imageTag)

	// Find and patch the DaemonSet
	for _, obj := range objs {
		if ds, ok := obj.(*appsv1.DaemonSet); ok {
			// Patch: Add EBPF_NETNS_FILTER_MODE env var and override image tag
			for i := range ds.Spec.Template.Spec.Containers {
				if ds.Spec.Template.Spec.Containers[i].Name == "ebpf-agent" {
					// Override image tag (FIX: Docker caching issue)
					ds.Spec.Template.Spec.Containers[i].Image = imageRef

					// Add filter mode env var
					ds.Spec.Template.Spec.Containers[i].Env = append(
						ds.Spec.Template.Spec.Containers[i].Env,
						corev1.EnvVar{
							Name:  "EBPF_NETNS_FILTER_MODE",
							Value: filterMode,
						},
					)
					break
				}
			}
		}

		// Apply patched resource
		if err := dm.r.Create(ctx, obj); err != nil {
			return fmt.Errorf("creating resource: %w", err)
		}
	}

	// Wait for DaemonSet to be ready
	return dm.waitForDaemonSetReady(ctx, "kubeadapt-system", "kubeadapt-ebpf-agent", 3*time.Minute)
}

// DeletePrometheus removes Prometheus deployment and all associated resources
// This ensures clean state before redeploying with fresh metrics
// Deletes: Deployment, ConfigMap, Service, ServiceAccount, ClusterRole, ClusterRoleBinding
func (dm *DeploymentManager) DeletePrometheus(ctx context.Context) error {
	// Delete Deployment
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus",
			Namespace: "monitoring",
		},
	}
	if err := dm.r.Delete(ctx, deploy); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting prometheus deployment: %w", err)
	}

	// Delete ConfigMap
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-config",
			Namespace: "monitoring",
		},
	}
	if err := dm.r.Delete(ctx, configMap); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting prometheus configmap: %w", err)
	}

	// Delete Service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus",
			Namespace: "monitoring",
		},
	}
	if err := dm.r.Delete(ctx, service); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting prometheus service: %w", err)
	}

	// Delete ServiceAccount
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus",
			Namespace: "monitoring",
		},
	}
	if err := dm.r.Delete(ctx, serviceAccount); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting prometheus serviceaccount: %w", err)
	}

	// Delete ClusterRole (cluster-scoped, no namespace)
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus",
		},
	}
	if err := dm.r.Delete(ctx, clusterRole); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting prometheus clusterrole: %w", err)
	}

	// Delete ClusterRoleBinding (cluster-scoped, no namespace)
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus",
		},
	}
	if err := dm.r.Delete(ctx, clusterRoleBinding); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting prometheus clusterrolebinding: %w", err)
	}

	// Wait for pods to terminate (max 2 minutes)
	if err := dm.waitForPodsGone(ctx, "monitoring", "app=prometheus", 2*time.Minute); err != nil {
		return fmt.Errorf("waiting for prometheus pods to terminate: %w", err)
	}

	// CRITICAL: Wait for ConfigMap to be fully deleted (asynchronous K8s operation)
	// Without this, immediate redeploy will fail with "already exists"
	// Extended timeout (2min) to handle slow finalizer execution on loaded systems
	return dm.waitForConfigMapGone(ctx, "monitoring", "prometheus-config", 2*time.Minute)
}

// DeleteAgent removes Agent DaemonSet, Service, and waits for all pods to terminate
func (dm *DeploymentManager) DeleteAgent(ctx context.Context) error {
	// Delete DaemonSet
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeadapt-ebpf-agent",
			Namespace: "kubeadapt-system",
		},
	}
	if err := dm.r.Delete(ctx, ds); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting daemonset: %w", err)
	}

	// Delete Service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeadapt-ebpf-agent",
			Namespace: "kubeadapt-system",
		},
	}
	if err := dm.r.Delete(ctx, service); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("deleting service: %w", err)
	}

	// Wait for pods to terminate (max 1 minute)
	return dm.waitForPodsGone(ctx, "kubeadapt-system", "app=kubeadapt-ebpf-agent", 1*time.Minute)
}

// waitForPrometheusReady waits for Prometheus deployment to be ready
func (dm *DeploymentManager) waitForPrometheusReady(ctx context.Context, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		var deploy appsv1.Deployment
		err := dm.r.Get(ctx, "prometheus", "monitoring", &deploy)
		if err != nil {
			return false, nil // Continue polling
		}

		// Check if all replicas are ready
		if deploy.Status.ReadyReplicas != *deploy.Spec.Replicas {
			return false, nil // Continue polling
		}

		return true, nil // Ready!
	})
}

// waitForDaemonSetReady waits for DaemonSet with comprehensive checks
// Verifies that ALL desired pods are ready, updated, and available
func (dm *DeploymentManager) waitForDaemonSetReady(ctx context.Context, namespace, name string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 3*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		var ds appsv1.DaemonSet
		err := dm.r.Get(ctx, name, namespace, &ds)
		if err != nil {
			return false, nil // Continue polling
		}

		// Check if daemonset has desired pods scheduled
		if ds.Status.DesiredNumberScheduled == 0 {
			return false, nil
		}

		// Check if all desired pods are ready
		if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
			return false, nil
		}

		// Check if all pods are updated to the latest version
		if ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
			return false, nil
		}

		// Check if all pods are available
		if ds.Status.NumberAvailable != ds.Status.DesiredNumberScheduled {
			return false, nil
		}

		return true, nil // Fully ready!
	})
}

// waitForPodsGone waits for all pods matching label selector to terminate
func (dm *DeploymentManager) waitForPodsGone(ctx context.Context, namespace, labelSelector string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		var podList corev1.PodList
		err := dm.r.WithNamespace(namespace).List(ctx, &podList)
		if err != nil {
			return false, err
		}

		// Count pods matching label selector
		matchingPods := 0
		for _, pod := range podList.Items {
			// Simple label matching (app label)
			if app, ok := pod.Labels["app"]; ok {
				if (labelSelector == "app=prometheus" && app == "prometheus") ||
					(labelSelector == "app=kubeadapt-ebpf-agent" && app == "kubeadapt-ebpf-agent") {
					matchingPods++
				}
			}
		}

		// All pods gone?
		return matchingPods == 0, nil
	})
}

// waitForConfigMapGone waits for a ConfigMap to be fully deleted
// This is critical for handling Kubernetes asynchronous deletion
func (dm *DeploymentManager) waitForConfigMapGone(ctx context.Context, namespace, name string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		var cm corev1.ConfigMap
		err := dm.r.Get(ctx, name, namespace, &cm)
		if errors.IsNotFound(err) {
			return true, nil // ConfigMap is gone!
		}
		if err != nil {
			return false, err // Unexpected error
		}
		return false, nil // ConfigMap still exists, keep waiting
	})
}

// testDataDir returns the testdata directory path
func testDataDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("can't find testdata directory")
	}
	return path.Join(path.Dir(file), "..", "testdata")
}
