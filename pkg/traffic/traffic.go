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
	stats.Requests++
	if r.IsHTTPS {
		stats.HTTPSCount++
	}
	stats.UniqueIPs[r.IP] = true
	stats.UniqueIPCount = len(stats.UniqueIPs)
}

// GetData returns a copy of the traffic data
func (m *Manager) GetData() *TrafficData {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy
	copy := &TrafficData{
		Records:       make([]RequestRecord, len(m.data.Records)),
		DomainStats:   make(map[string]*DomainStats),
		TotalReqs:     m.data.TotalReqs,
		HTTPSReqs:     m.data.HTTPSReqs,
		UniqueIPCount: m.data.UniqueIPCount,
		LastSaved:     m.data.LastSaved,
	}

	copy.Records = append(copy.Records[:0], m.data.Records...)

	for k, v := range m.data.DomainStats {
		copy.DomainStats[k] = &DomainStats{
			Domain:        v.Domain,
			Requests:      v.Requests,
			HTTPSCount:    v.HTTPSCount,
			UniqueIPCount: v.UniqueIPCount,
		}
	}

	return copy
}

// saveData saves data to file
func (m *Manager) saveData() error {
	m.mu.RLock()
	m.data.LastSaved = time.Now()
	data := *m.data
	m.mu.RUnlock()

	// Clean up internal maps before saving
	data.UniqueIPs = nil
	for _, stats := range data.DomainStats {
		stats.UniqueIPs = nil
	}

	filename := filepath.Join(m.dataDir, "traffic.json")
	tmpFile := filename + ".tmp"

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
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
	close(m.stopChan)
}
