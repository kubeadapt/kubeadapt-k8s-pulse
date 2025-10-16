package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	k8scache "k8s.io/client-go/tools/cache"
)

// KubernetesDiscoverer discovers containers using Kubernetes API
type KubernetesDiscoverer struct {
	client    kubernetes.Interface
	namespace string
	nodeName  string
	logger    *zap.Logger
}

// NewKubernetesDiscoverer creates a new Kubernetes-based container discoverer
func NewKubernetesDiscoverer(namespace string, logger *zap.Logger) (*KubernetesDiscoverer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Create Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("creating in-cluster config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	// Get node name from environment or hostname
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	return &KubernetesDiscoverer{
		client:    client,
		namespace: namespace,
		nodeName:  nodeName,
		logger:    logger,
	}, nil
}

// Start begins the discovery process
func (d *KubernetesDiscoverer) Start(ctx context.Context, containerCache *Cache) error {
	d.logger.Info("Starting Kubernetes container discovery",
		zap.String("namespace", d.namespace),
		zap.String("node", d.nodeName),
	)

	// Initial sync
	if err := d.syncContainers(ctx, containerCache); err != nil {
		d.logger.Error("Initial sync failed", zap.Error(err))
	}

	// Setup watch for pod changes
	watchlist := k8scache.NewListWatchFromClient(
		d.client.CoreV1().RESTClient(),
		"pods",
		d.namespace, // Empty string means all namespaces
		fields.OneTermEqualSelector("spec.nodeName", d.nodeName),
	)

	// Note: Using deprecated NewInformer is acceptable here as it's still supported
	// The newer SharedIndexInformer would require more complex setup
	//nolint:staticcheck // SA1019: NewInformer is deprecated but still functional
	_, controller := k8scache.NewInformer(
		watchlist,
		&corev1.Pod{},
		30*time.Second,
		k8scache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				d.handlePodUpdate(pod, containerCache)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				pod := newObj.(*corev1.Pod)
				d.handlePodUpdate(pod, containerCache)
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				d.handlePodDelete(pod, containerCache)
			},
		},
	)

	// Run controller
	go controller.Run(ctx.Done())

	// Periodic full sync to catch any missed updates
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("Stopping Kubernetes discovery")
			return nil
		case <-ticker.C:
			if err := d.syncContainers(ctx, containerCache); err != nil {
				d.logger.Error("Periodic sync failed", zap.Error(err))
			}
		}
	}
}

// syncContainers performs a full sync of all containers
func (d *KubernetesDiscoverer) syncContainers(ctx context.Context, containerCache *Cache) error {
	d.logger.Debug("Syncing containers from Kubernetes")

	// List pods on this node
	opts := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", d.nodeName).String(),
	}

	if d.namespace != "" {
		pods, err := d.client.CoreV1().Pods(d.namespace).List(ctx, opts)
		if err != nil {
			return fmt.Errorf("listing pods in namespace %s: %w", d.namespace, err)
		}
		for i := range pods.Items {
			d.handlePodUpdate(&pods.Items[i], containerCache)
		}
	} else {
		// List all namespaces
		pods, err := d.client.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return fmt.Errorf("listing all pods: %w", err)
		}
		for i := range pods.Items {
			d.handlePodUpdate(&pods.Items[i], containerCache)
		}
	}

	stats := containerCache.Stats()
	d.logger.Info("Container sync completed",
		zap.Int("total_containers", stats.TotalContainers),
		zap.Int("cgroup_mappings", stats.CgroupMappings),
		zap.Int("pods", stats.PodCount),
	)

	return nil
}

// handlePodUpdate processes a pod add/update event
func (d *KubernetesDiscoverer) handlePodUpdate(pod *corev1.Pod, containerCache *Cache) {
	d.logger.Debug("Processing pod update",
		zap.String("pod", pod.Name),
		zap.String("namespace", pod.Namespace),
		zap.Int("containers", len(pod.Status.ContainerStatuses)),
	)

	// Process each container
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running == nil {
			continue
		}

		// Extract container ID (format: docker://abc123... or containerd://abc123...)
		containerID := extractContainerID(containerStatus.ContainerID)
		if containerID == "" {
			continue
		}

		// Get cgroup ID
		cgroupID := d.getCgroupID(pod, containerStatus.Name, containerID)

		info := &Info{
			ContainerID:   containerID,
			ContainerName: containerStatus.Name,
			PodName:       pod.Name,
			Namespace:     pod.Namespace,
			NodeName:      pod.Spec.NodeName,
			CgroupID:      cgroupID,
			Labels:        pod.Labels,
			Annotations:   pod.Annotations,
			StartTime:     containerStatus.State.Running.StartedAt.Time,
		}

		// Extract runtime type
		if strings.HasPrefix(containerStatus.ContainerID, "docker://") {
			info.RuntimeType = "docker"
		} else if strings.HasPrefix(containerStatus.ContainerID, "containerd://") {
			info.RuntimeType = "containerd"
		} else if strings.HasPrefix(containerStatus.ContainerID, "cri-o://") {
			info.RuntimeType = "cri-o"
		}

		// Add resource limits if specified
		for _, container := range pod.Spec.Containers {
			if container.Name == containerStatus.Name {
				if limits := container.Resources.Limits; limits != nil {
					if cpu := limits.Cpu(); cpu != nil {
						info.CPULimit = cpu.MilliValue()
					}
					if mem := limits.Memory(); mem != nil {
						info.MemoryLimit = mem.Value()
					}
				}
				break
			}
		}

		containerCache.Add(info)
		d.logger.Debug("Added container to cache",
			zap.String("container", containerStatus.Name),
			zap.String("id", containerID),
			zap.Uint64("cgroup", cgroupID),
		)
	}
}

// handlePodDelete processes a pod deletion event
func (d *KubernetesDiscoverer) handlePodDelete(pod *corev1.Pod, containerCache *Cache) {
	d.logger.Debug("Processing pod deletion",
		zap.String("pod", pod.Name),
		zap.String("namespace", pod.Namespace),
	)

	// Remove all containers from this pod
	for _, containerStatus := range pod.Status.ContainerStatuses {
		containerID := extractContainerID(containerStatus.ContainerID)
		if containerID != "" {
			containerCache.Remove(containerID)
			d.logger.Debug("Removed container from cache",
				zap.String("container", containerStatus.Name),
				zap.String("id", containerID),
			)
		}
	}
}

// getCgroupID extracts the cgroup ID for a container
func (d *KubernetesDiscoverer) getCgroupID(pod *corev1.Pod, containerName, containerID string) uint64 {
	// Try multiple methods to get cgroup ID

	// Method 1: Read from /sys/fs/cgroup path
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/kubepods.slice/kubepods-pod%s.slice/docker-%s.scope",
		strings.ReplaceAll(string(pod.UID), "-", "_"), containerID)

	if cgroupID := readCgroupIDFromPath(cgroupPath); cgroupID != 0 {
		return cgroupID
	}

	// Method 2: Try containerd path
	cgroupPath = fmt.Sprintf("/sys/fs/cgroup/kubepods.slice/kubepods-pod%s.slice/cri-containerd-%s.scope",
		strings.ReplaceAll(string(pod.UID), "-", "_"), containerID)

	if cgroupID := readCgroupIDFromPath(cgroupPath); cgroupID != 0 {
		return cgroupID
	}

	// Method 3: Try systemd path
	cgroupPath = fmt.Sprintf("/sys/fs/cgroup/system.slice/containerd.service/kubepods-pod%s.slice/cri-containerd-%s.scope",
		strings.ReplaceAll(string(pod.UID), "-", "_"), containerID)

	if cgroupID := readCgroupIDFromPath(cgroupPath); cgroupID != 0 {
		return cgroupID
	}

	// Method 4: Search in /proc for container process
	if cgroupID := d.getCgroupIDFromProc(containerID); cgroupID != 0 {
		return cgroupID
	}

	d.logger.Warn("Could not determine cgroup ID",
		zap.String("pod", pod.Name),
		zap.String("container", containerName),
		zap.String("containerID", containerID),
	)

	return 0
}

// getCgroupIDFromProc searches /proc for the container's cgroup ID
func (d *KubernetesDiscoverer) getCgroupIDFromProc(containerID string) uint64 {
	procDir := "/host/proc"
	if _, err := os.Stat(procDir); os.IsNotExist(err) {
		procDir = "/proc"
	}

	entries, err := os.ReadDir(procDir)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if this is a PID directory
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read the cgroup file
		cgroupFile := filepath.Join(procDir, entry.Name(), "cgroup")
		data, err := os.ReadFile(cgroupFile)
		if err != nil {
			continue
		}

		// Check if this process belongs to our container
		if strings.Contains(string(data), containerID) {
			// Extract cgroup ID from the path
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.Contains(line, "0::") { // cgroup v2
					parts := strings.Split(line, "::")
					if len(parts) >= 2 {
						return extractCgroupIDFromPath(parts[1])
					}
				}
			}
		}

		_ = pid // Use pid to avoid unused variable warning
	}

	return 0
}

// readCgroupIDFromPath reads the cgroup ID from a cgroup path
func readCgroupIDFromPath(path string) uint64 {
	// Get the inode number of the cgroup directory
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}

	// Extract inode from file info
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}

	return 0
}

// extractCgroupIDFromPath extracts cgroup ID from a cgroup path string
func extractCgroupIDFromPath(path string) uint64 {
	// The cgroup ID is typically the inode of the cgroup directory
	// For now, we'll use a hash of the path as a simple ID
	// In production, you'd want to get the actual inode

	// Try to extract from systemd path
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.Contains(part, ".scope") || strings.Contains(part, ".slice") {
			// Simple hash for demo - in production use actual inode
			var hash uint64
			for _, c := range part {
				hash = hash*31 + uint64(c)
			}
			return hash
		}
	}

	return 0
}

// extractContainerID extracts the container ID from the full container ID string
func extractContainerID(fullID string) string {
	// Format: docker://abc123... or containerd://abc123...
	parts := strings.SplitN(fullID, "://", 2)
	if len(parts) == 2 {
		// Take first 12 characters of ID for consistency
		id := parts[1]
		if len(id) > 12 {
			return id[:12]
		}
		return id
	}
	return ""
}

// Name returns the discoverer name
func (d *KubernetesDiscoverer) Name() string {
	return "kubernetes"
}
