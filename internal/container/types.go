package container

import (
	"sync"
	"time"
)

// Info represents container metadata
type Info struct {
	// Container identification
	ContainerID   string
	ContainerName string
	PodName       string
	Namespace     string
	NodeName      string

	// Cgroup information
	CgroupID   uint64
	CgroupPath string

	// Additional metadata
	Labels      map[string]string
	Annotations map[string]string

	// Runtime information
	RuntimeType string // docker, containerd, cri-o
	PID         int
	StartTime   time.Time

	// Resource limits (optional)
	CPULimit    int64 // in millicores
	MemoryLimit int64 // in bytes
}

// Cache stores container information with thread-safe access
type Cache struct {
	mu sync.RWMutex

	// Maps for different lookups
	byID       map[string]*Info      // containerID -> Info
	byCgroup   map[uint64]*Info      // cgroupID -> Info
	byPod      map[string][]*Info    // podName -> []Info

	// Metrics
	lastUpdate time.Time
	totalCount int
}

// NewCache creates a new container cache
func NewCache() *Cache {
	return &Cache{
		byID:     make(map[string]*Info),
		byCgroup: make(map[uint64]*Info),
		byPod:    make(map[string][]*Info),
	}
}

// Add adds or updates a container in the cache
func (c *Cache) Add(info *Info) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Add to all maps
	c.byID[info.ContainerID] = info

	if info.CgroupID != 0 {
		c.byCgroup[info.CgroupID] = info
	}

	if info.PodName != "" {
		// Update pod map
		found := false
		for i, existing := range c.byPod[info.PodName] {
			if existing.ContainerID == info.ContainerID {
				c.byPod[info.PodName][i] = info
				found = true
				break
			}
		}
		if !found {
			c.byPod[info.PodName] = append(c.byPod[info.PodName], info)
		}
	}

	c.lastUpdate = time.Now()
	c.totalCount = len(c.byID)
}

// GetByCgroup retrieves container info by cgroup ID
func (c *Cache) GetByCgroup(cgroupID uint64) (*Info, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, ok := c.byCgroup[cgroupID]
	return info, ok
}

// GetByID retrieves container info by container ID
func (c *Cache) GetByID(containerID string) (*Info, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, ok := c.byID[containerID]
	return info, ok
}

// GetByPod retrieves all containers for a pod
func (c *Cache) GetByPod(podName string) ([]*Info, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	infos, ok := c.byPod[podName]
	return infos, ok
}

// List returns all containers in the cache
func (c *Cache) List() []*Info {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*Info, 0, len(c.byID))
	for _, info := range c.byID {
		result = append(result, info)
	}
	return result
}

// Remove removes a container from the cache
func (c *Cache) Remove(containerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, ok := c.byID[containerID]
	if !ok {
		return
	}

	// Remove from all maps
	delete(c.byID, containerID)

	if info.CgroupID != 0 {
		delete(c.byCgroup, info.CgroupID)
	}

	if info.PodName != "" {
		pods := c.byPod[info.PodName]
		for i, existing := range pods {
			if existing.ContainerID == containerID {
				// Remove from slice
				c.byPod[info.PodName] = append(pods[:i], pods[i+1:]...)
				if len(c.byPod[info.PodName]) == 0 {
					delete(c.byPod, info.PodName)
				}
				break
			}
		}
	}

	c.totalCount = len(c.byID)
}

// Clear removes all containers from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.byID = make(map[string]*Info)
	c.byCgroup = make(map[uint64]*Info)
	c.byPod = make(map[string][]*Info)
	c.totalCount = 0
}

// Stats returns cache statistics
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CacheStats{
		TotalContainers: c.totalCount,
		CgroupMappings:  len(c.byCgroup),
		PodCount:        len(c.byPod),
		LastUpdate:      c.lastUpdate,
	}
}

// CacheStats represents cache statistics
type CacheStats struct {
	TotalContainers int
	CgroupMappings  int
	PodCount        int
	LastUpdate      time.Time
}

// Discoverer interface for container discovery
type Discoverer interface {
	// Start begins the discovery process
	Start(ctx context.Context, cache *Cache) error

	// Name returns the discoverer name
	Name() string
}