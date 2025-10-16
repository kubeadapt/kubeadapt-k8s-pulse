package k8s

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// PodMetadata contains all metadata for a pod
type PodMetadata struct {
	Name        string
	Namespace   string
	IP          string
	NodeName    string
	Labels      map[string]string
	Annotations map[string]string
	LastUpdated time.Time
}

// NodeMetadata contains info for nodes
type NodeMetadata struct {
	Name        string
	IPs         []string // All node IPs (internal, external)
	LastUpdated time.Time
}

// PodMetadataCache provides real-time pod metadata using Kubernetes Informers
// This cache is automatically updated via the K8s watch API when pods/nodes change
type PodMetadataCache struct {
	client kubernetes.Interface
	logger *zap.Logger

	// Caches with multiple indexes for fast lookup
	mu          sync.RWMutex
	podsByIP    map[string]*PodMetadata  // IP -> Pod metadata
	podsByName  map[string]*PodMetadata  // namespace/name -> Pod metadata
	nodesByName map[string]*NodeMetadata // node name -> Node metadata
	nodesByIP   map[string]*NodeMetadata // node IP -> Node metadata

	// Informers for real-time updates
	podInformer  cache.SharedIndexInformer
	nodeInformer cache.SharedIndexInformer
	stopCh       chan struct{}

	// Metrics for monitoring
	cacheHits   uint64
	cacheMisses uint64
	apiCalls    uint64
	updates     uint64
}

// NewPodMetadataCache creates a new cache with Kubernetes informers
func NewPodMetadataCache(logger *zap.Logger) (*PodMetadataCache, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// For local development, return cache without client
		logger.Debug("Failed to create in-cluster config, running without K8s integration", zap.Error(err))
		return &PodMetadataCache{
			logger:      logger,
			podsByIP:    make(map[string]*PodMetadata),
			podsByName:  make(map[string]*PodMetadata),
			nodesByName: make(map[string]*NodeMetadata),
			nodesByIP:   make(map[string]*NodeMetadata),
			stopCh:      make(chan struct{}),
		}, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	cache := &PodMetadataCache{
		client:      client,
		logger:      logger,
		podsByIP:    make(map[string]*PodMetadata),
		podsByName:  make(map[string]*PodMetadata),
		nodesByName: make(map[string]*NodeMetadata),
		nodesByIP:   make(map[string]*NodeMetadata),
		stopCh:      make(chan struct{}),
	}

	// Create informers for pods and nodes
	if err := cache.setupInformers(); err != nil {
		return nil, fmt.Errorf("failed to setup informers: %w", err)
	}

	return cache, nil
}

// setupInformers creates and starts the Kubernetes informers
func (c *PodMetadataCache) setupInformers() error {
	// Create Pod informer
	podListWatcher := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return c.client.CoreV1().Pods("").List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return c.client.CoreV1().Pods("").Watch(context.TODO(), options)
		},
	}

	c.podInformer = cache.NewSharedIndexInformer(
		podListWatcher,
		&v1.Pod{},
		30*time.Second, // Resync period
		cache.Indexers{},
	)

	// Add pod event handlers
	// Note: AddEventHandler returns a ResourceEventHandlerRegistration
	// which we can ignore as we don't need to remove handlers
	_, _ = c.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onPodAdd,
		UpdateFunc: c.onPodUpdate,
		DeleteFunc: c.onPodDelete,
	})

	// Create Node informer
	nodeListWatcher := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return c.client.CoreV1().Nodes().List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return c.client.CoreV1().Nodes().Watch(context.TODO(), options)
		},
	}

	c.nodeInformer = cache.NewSharedIndexInformer(
		nodeListWatcher,
		&v1.Node{},
		30*time.Second, // Resync period
		cache.Indexers{},
	)

	// Add node event handlers
	// Note: AddEventHandler returns a ResourceEventHandlerRegistration
	// which we can ignore as we don't need to remove handlers
	_, _ = c.nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onNodeAdd,
		UpdateFunc: c.onNodeUpdate,
		DeleteFunc: c.onNodeDelete,
	})

	return nil
}

// Start begins watching for Kubernetes events
func (c *PodMetadataCache) Start() error {
	if c.client == nil {
		c.logger.Info("PodMetadataCache running without Kubernetes integration")
		return nil
	}

	c.logger.Info("Starting PodMetadataCache informers")

	// Start informers in background
	go c.podInformer.Run(c.stopCh)
	go c.nodeInformer.Run(c.stopCh)

	// Wait for initial cache sync
	c.logger.Info("Waiting for informer caches to sync")
	if !cache.WaitForCacheSync(c.stopCh, c.podInformer.HasSynced, c.nodeInformer.HasSynced) {
		return fmt.Errorf("failed to sync informer caches")
	}

	c.logger.Info("PodMetadataCache ready",
		zap.Int("pods", len(c.podsByIP)),
		zap.Int("nodes", len(c.nodesByName)))

	return nil
}

// Stop stops the informers
func (c *PodMetadataCache) Stop() {
	close(c.stopCh)
}

// GetPodForIP returns the pod name for an IP address
func (c *PodMetadataCache) GetPodForIP(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if pod, exists := c.podsByIP[ip]; exists {
		c.cacheHits++
		return pod.Name
	}

	c.cacheMisses++
	return ""
}

// GetNamespaceForIP returns the namespace for an IP address
func (c *PodMetadataCache) GetNamespaceForIP(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if pod, exists := c.podsByIP[ip]; exists {
		c.cacheHits++
		return pod.Namespace
	}

	c.cacheMisses++
	return ""
}

// GetServiceForPod returns the service name for a pod (if it belongs to one)
func (c *PodMetadataCache) GetServiceForPod(namespace, podName string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := namespace + "/" + podName
	if pod, exists := c.podsByName[key]; exists {
		// Check for common service labels
		if svc, ok := pod.Labels["app"]; ok {
			return svc
		}
		if svc, ok := pod.Labels["app.kubernetes.io/name"]; ok {
			return svc
		}
		if svc, ok := pod.Labels["k8s-app"]; ok {
			return svc
		}
	}
	return ""
}

// GetStats returns cache statistics
func (c *PodMetadataCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hitRate := float64(0)
	if total := c.cacheHits + c.cacheMisses; total > 0 {
		hitRate = float64(c.cacheHits) / float64(total) * 100
	}

	return map[string]interface{}{
		"pods_cached":    len(c.podsByIP),
		"nodes_cached":   len(c.nodesByName),
		"cache_hits":     c.cacheHits,
		"cache_misses":   c.cacheMisses,
		"cache_hit_rate": hitRate,
		"api_calls":      c.apiCalls,
		"updates":        c.updates,
	}
}

// Pod informer event handlers
func (c *PodMetadataCache) onPodAdd(obj interface{}) {
	pod := obj.(*v1.Pod)
	c.updatePodCache(pod)
	c.logger.Debug("Pod added to cache",
		zap.String("pod", pod.Name),
		zap.String("namespace", pod.Namespace),
		zap.String("ip", pod.Status.PodIP))
}

func (c *PodMetadataCache) onPodUpdate(oldObj, newObj interface{}) {
	pod := newObj.(*v1.Pod)
	c.updatePodCache(pod)
	c.updates++
}

func (c *PodMetadataCache) onPodDelete(obj interface{}) {
	pod := obj.(*v1.Pod)
	c.removePodFromCache(pod)
	c.logger.Debug("Pod removed from cache",
		zap.String("pod", pod.Name),
		zap.String("namespace", pod.Namespace))
}

// Node informer event handlers
func (c *PodMetadataCache) onNodeAdd(obj interface{}) {
	node := obj.(*v1.Node)
	c.updateNodeCache(node)
	c.logger.Debug("Node added to cache", zap.String("node", node.Name))
}

func (c *PodMetadataCache) onNodeUpdate(oldObj, newObj interface{}) {
	node := newObj.(*v1.Node)
	c.updateNodeCache(node)
	c.updates++
}

func (c *PodMetadataCache) onNodeDelete(obj interface{}) {
	node := obj.(*v1.Node)
	c.removeNodeFromCache(node)
	c.logger.Debug("Node removed from cache", zap.String("node", node.Name))
}

// updatePodCache updates the cache with pod metadata
func (c *PodMetadataCache) updatePodCache(pod *v1.Pod) {
	if pod.Status.PodIP == "" {
		return // Pod doesn't have an IP yet
	}

	metadata := &PodMetadata{
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		IP:          pod.Status.PodIP,
		NodeName:    pod.Spec.NodeName,
		Labels:      pod.Labels,
		Annotations: pod.Annotations,
		LastUpdated: time.Now(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Update both indexes
	c.podsByIP[pod.Status.PodIP] = metadata
	c.podsByName[pod.Namespace+"/"+pod.Name] = metadata
}

// removePodFromCache removes a pod from the cache
func (c *PodMetadataCache) removePodFromCache(pod *v1.Pod) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if pod.Status.PodIP != "" {
		delete(c.podsByIP, pod.Status.PodIP)
	}
	delete(c.podsByName, pod.Namespace+"/"+pod.Name)
}

// updateNodeCache updates the cache with node metadata
func (c *PodMetadataCache) updateNodeCache(node *v1.Node) {
	// Collect all node IPs
	var ips []string
	for _, addr := range node.Status.Addresses {
		if addr.Type == v1.NodeInternalIP || addr.Type == v1.NodeExternalIP {
			ips = append(ips, addr.Address)
		}
	}

	metadata := &NodeMetadata{
		Name:        node.Name,
		IPs:         ips,
		LastUpdated: time.Now(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Update node cache
	c.nodesByName[node.Name] = metadata

	// Update IP index
	for _, ip := range ips {
		c.nodesByIP[ip] = metadata
	}
}

// removeNodeFromCache removes a node from the cache
func (c *PodMetadataCache) removeNodeFromCache(node *v1.Node) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if metadata, exists := c.nodesByName[node.Name]; exists {
		// Remove from IP index
		for _, ip := range metadata.IPs {
			delete(c.nodesByIP, ip)
		}
		// Remove from name index
		delete(c.nodesByName, node.Name)
	}
}
