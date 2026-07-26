package traffic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

const (
	maxRecordsInMemory = 10000
	dataRetentionDays  = 30
	saveInterval       = 5 * time.Minute
	uniqueRebuildEvery = 1000
)

// RequestRecord represents a single request record
type RequestRecord struct {
	Timestamp  time.Time `json:"ts"`
	Domain     string    `json:"domain"`
	IP         string    `json:"ip"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status"`
	IsHTTPS    bool      `json:"https"`
	UserAgent  string    `json:"ua"`
}

// DomainStats represents aggregated statistics for a domain
type DomainStats struct {
	Domain        string          `json:"domain"`
	Requests      int64           `json:"requests"`
	HTTPSCount    int64           `json:"https_count"`
	UniqueIPs     map[string]bool `json:"-"`
	UniqueIPCount int             `json:"unique_ips"`
}

// TrafficData holds all traffic data
type TrafficData struct {
	Records       []RequestRecord         `json:"records"`
	DomainStats   map[string]*DomainStats `json:"domain_stats"`
	TotalReqs     int64                   `json:"total_requests"`
	HTTPSReqs     int64                   `json:"https_requests"`
	UniqueIPs     map[string]bool         `json:"-"`
	UniqueIPCount int                     `json:"unique_ips"`
	LastSaved     time.Time               `json:"last_saved"`
}

// Manager manages traffic data collection and storage
type Manager struct {
	data       *TrafficData
	dataDir    string
	recordChan chan RequestRecord
	stopChan   chan struct{}
	mu         sync.RWMutex
	evictions  int
	stopOnce   sync.Once
}

// NewManager creates a new traffic manager
func NewManager(dataDir string) *Manager {
	m := &Manager{
		data: &TrafficData{
			Records:     make([]RequestRecord, 0, maxRecordsInMemory),
			DomainStats: make(map[string]*DomainStats),
			UniqueIPs:   make(map[string]bool),
		},
		dataDir:    dataDir,
		recordChan: make(chan RequestRecord, 1000),
		stopChan:   make(chan struct{}),
	}

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Error("Failed to create traffic data directory", "err", err)
	}

	m.loadData()
	go m.processRecords()
	go m.periodicSave()

	return m
}

// Record records a new request
func (m *Manager) Record(r RequestRecord) {
	r.Domain = truncate(r.Domain, 253)
	r.IP = truncate(r.IP, 64)
	r.Method = truncate(r.Method, 16)
	r.Path = truncate(r.Path, 2048)
	r.UserAgent = truncate(r.UserAgent, 512)
	select {
	case m.recordChan <- r:
	default:
		// Channel full, drop record to avoid blocking
	}
}

// processRecords processes incoming records
func (m *Manager) processRecords() {
	for {
		select {
		case record := <-m.recordChan:
			m.addRecord(record)
		case <-m.stopChan:
			return
		}
	}
}

// addRecord adds a record to the data
func (m *Manager) addRecord(r RequestRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to records
	m.data.Records = append(m.data.Records, r)
	if len(m.data.Records) > maxRecordsInMemory {
		m.data.Records = m.data.Records[len(m.data.Records)-maxRecordsInMemory:]
		m.evictions++
		if m.evictions >= uniqueRebuildEvery {
			m.rebuildUniqueIPsLocked()
			m.evictions = 0
		}
	}

	// Update stats
	m.data.TotalReqs++
	if r.IsHTTPS {
		m.data.HTTPSReqs++
	}

	// Unique IPs
	m.data.UniqueIPs[r.IP] = true
	m.data.UniqueIPCount = len(m.data.UniqueIPs)

	// Domain stats
	stats, exists := m.data.DomainStats[r.Domain]
	if !exists {
		stats = &DomainStats{
			Domain:    r.Domain,
			UniqueIPs: make(map[string]bool),
		}
		m.data.DomainStats[r.Domain] = stats
	}
	if stats.UniqueIPs == nil {
		stats.UniqueIPs = make(map[string]bool)
	}
	stats.Requests++
	if r.IsHTTPS {
		stats.HTTPSCount++
	}
	stats.UniqueIPs[r.IP] = true
	stats.UniqueIPCount = len(stats.UniqueIPs)
}

func (m *Manager) rebuildUniqueIPsLocked() {
	m.data.UniqueIPs = make(map[string]bool)
	for _, stats := range m.data.DomainStats {
		stats.UniqueIPs = make(map[string]bool)
		stats.UniqueIPCount = 0
	}
	for _, record := range m.data.Records {
		m.data.UniqueIPs[record.IP] = true
		if stats := m.data.DomainStats[record.Domain]; stats != nil {
			stats.UniqueIPs[record.IP] = true
			stats.UniqueIPCount = len(stats.UniqueIPs)
		}
	}
	m.data.UniqueIPCount = len(m.data.UniqueIPs)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

// GetData returns a copy of the traffic data
func (m *Manager) GetData() *TrafficData {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotLocked(len(m.data.Records))
}

// GetRecentData returns aggregate stats plus only the newest records. The WebUI
// never renders the full retention buffer, so this avoids copying and encoding
// thousands of unused entries on every poll.
func (m *Manager) GetRecentData(limit int) *TrafficData {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotLocked(limit)
}

func (m *Manager) snapshotLocked(limit int) *TrafficData {
	start := 0
	if limit >= 0 && len(m.data.Records) > limit {
		start = len(m.data.Records) - limit
	}
	snapshot := &TrafficData{
		Records:       append([]RequestRecord(nil), m.data.Records[start:]...),
		DomainStats:   make(map[string]*DomainStats),
		TotalReqs:     m.data.TotalReqs,
		HTTPSReqs:     m.data.HTTPSReqs,
		UniqueIPCount: m.data.UniqueIPCount,
		LastSaved:     m.data.LastSaved,
	}

	for k, v := range m.data.DomainStats {
		snapshot.DomainStats[k] = &DomainStats{
			Domain:        v.Domain,
			Requests:      v.Requests,
			HTTPSCount:    v.HTTPSCount,
			UniqueIPCount: v.UniqueIPCount,
		}
	}

	return snapshot
}

// saveData saves data to file
func (m *Manager) saveData() error {
	m.mu.Lock()
	m.data.LastSaved = time.Now()
	data := m.snapshotLocked(len(m.data.Records))
	m.mu.Unlock()

	filename := filepath.Join(m.dataDir, "traffic.json")
	tmpFile := filename + ".tmp"

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if err := os.WriteFile(tmpFile, jsonData, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, filename)
}

// loadData loads data from file
func (m *Manager) loadData() error {
	filename := filepath.Join(m.dataDir, "traffic.json")

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var loaded TrafficData
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Error("Failed to unmarshal traffic data", "err", err)
		return err
	}

	// Rebuild internal maps
	loaded.UniqueIPs = make(map[string]bool)
	for _, record := range loaded.Records {
		loaded.UniqueIPs[record.IP] = true
		if stats, exists := loaded.DomainStats[record.Domain]; exists {
			if stats.UniqueIPs == nil {
				stats.UniqueIPs = make(map[string]bool)
			}
			stats.UniqueIPs[record.IP] = true
			stats.UniqueIPCount = len(stats.UniqueIPs)
		}
	}
	loaded.UniqueIPCount = len(loaded.UniqueIPs)

	// Clean old records and rebuild UniqueIPs
	cutoff := time.Now().AddDate(0, 0, -dataRetentionDays)
	filtered := make([]RequestRecord, 0, len(loaded.Records))
	newUniqueIPs := make(map[string]bool)
	newDomainIPs := make(map[string]map[string]bool) // domain -> set of IPs

	for _, r := range loaded.Records {
		if r.Timestamp.After(cutoff) {
			filtered = append(filtered, r)
			newUniqueIPs[r.IP] = true
			if _, ok := newDomainIPs[r.Domain]; !ok {
				newDomainIPs[r.Domain] = make(map[string]bool)
			}
			newDomainIPs[r.Domain][r.IP] = true
		}
	}
	loaded.Records = filtered
	loaded.UniqueIPs = newUniqueIPs
	loaded.UniqueIPCount = len(newUniqueIPs)

	// Rebuild domain stats UniqueIPs
	for domain, stats := range loaded.DomainStats {
		if ips, ok := newDomainIPs[domain]; ok {
			stats.UniqueIPs = ips
			stats.UniqueIPCount = len(ips)
		} else {
			// No records for this domain anymore, reset
			stats.UniqueIPs = make(map[string]bool)
			stats.UniqueIPCount = 0
		}
	}

	m.data = &loaded
	log.Info("Loaded traffic data", "records", len(loaded.Records), "domains", len(loaded.DomainStats), "unique_ips", loaded.UniqueIPCount)
	return nil
}

// periodicSave periodically saves data to file
func (m *Manager) periodicSave() {
	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.saveData(); err != nil {
				log.Error("Failed to save traffic data", "err", err)
			}
		case <-m.stopChan:
			if err := m.saveData(); err != nil {
				log.Error("Failed to save traffic data on stop", "err", err)
			}
			return
		}
	}
}

// Stop stops the manager
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopChan) })
}
