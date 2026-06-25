package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type ContainerInfo struct {
	ID              string         `json:"Id"`
	Name            string         `json:"Name"`
	Image           string         `json:"Image"`
	NetworkSettings NetworkSettings `json:"NetworkSettings"`
	IPs             []string       `json:"-"`
}

type NetworkSettings struct {
	Networks map[string]Network `json:"Networks"`
}

type Network struct {
	IPAddress string `json:"IPAddress"`
}

type Client struct {
	httpClient *http.Client
	cache      map[string]*ContainerInfo
	cacheTime  time.Time
	cacheMutex sync.RWMutex
	cacheTTL   time.Duration
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.DialTimeout("unix", "/var/run/docker.sock", 5*time.Second)
				},
			},
			Timeout: 10 * time.Second,
		},
		cache:    make(map[string]*ContainerInfo),
		cacheTTL: 30 * time.Second,
	}
}

func (c *Client) ListContainers() ([]*ContainerInfo, error) {
	req, err := http.NewRequest("GET", "http://localhost/containers/json", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Docker API error: %s", resp.Status)
	}
	var containers []*ContainerInfo
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return containers, nil
}

func (c *Client) GetContainerByIP(ip string) *ContainerInfo {
	c.cacheMutex.RLock()
	if time.Since(c.cacheTime) < c.cacheTTL {
		if info, ok := c.cache[ip]; ok {
			c.cacheMutex.RUnlock()
			return info
		}
	}
	c.cacheMutex.RUnlock()
	c.refreshCache()
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	return c.cache[ip]
}

func (c *Client) refreshCache() {
	containers, err := c.ListContainers()
	if err != nil {
		log.Printf("[DOCKER] 刷新容器缓存失败: %v", err)
		return
	}
	newCache := make(map[string]*ContainerInfo)
	for _, container := range containers {
		container.IPs = extractIPs(container)
		for _, ip := range container.IPs {
			newCache[ip] = container
		}
	}
	c.cacheMutex.Lock()
	c.cache = newCache
	c.cacheTime = time.Now()
	c.cacheMutex.Unlock()
	log.Printf("[DOCKER] 容器缓存已刷新，共 %d 个容器", len(containers))
}

func extractIPs(container *ContainerInfo) []string {
	var ips []string
	for _, network := range container.NetworkSettings.Networks {
		if network.IPAddress != "" {
			ips = append(ips, network.IPAddress)
		}
	}
	return ips
}

func (c *Client) GetContainerName(ip string) string {
	info := c.GetContainerByIP(ip)
	if info == nil {
		return ""
	}
	if len(info.Name) > 0 && info.Name[0] == '/' {
		return info.Name[1:]
	}
	return info.Name
}

func (c *Client) GetContainerID(ip string) string {
	info := c.GetContainerByIP(ip)
	if info == nil {
		return ""
	}
	if len(info.ID) >= 12 {
		return info.ID[:12]
	}
	return info.ID
}
