package types

import "time"

// Directory represents the relay directory structure
type Directory struct {
	Version int     `json:"version"`
	Updated string  `json:"updated"`
	Relays  []Relay `json:"relays"`
}

// Relay represents a single relay entry
type Relay struct {
	Name    string   `json:"name"`
	PubKey  string   `json:"pubkey"`
	Address string   `json:"address"`
	Roles   []string `json:"roles"`
}

// HealthReport is the output of a health check run
type HealthReport struct {
	CheckedAt     time.Time     `json:"checked_at"`
	NetworkHealth NetworkHealth `json:"network_health"`
	Relays        []RelayHealth `json:"relays"`
}

// NetworkHealth summarizes overall network status
type NetworkHealth struct {
	TotalRelays int     `json:"total_relays"`
	Healthy     int     `json:"healthy"`
	Degraded    int     `json:"degraded"`
	Offline     int     `json:"offline"`
	Score       float64 `json:"score"`
}

// RelayHealth represents health status of a single relay
type RelayHealth struct {
	Name    string       `json:"name"`
	Address string       `json:"address"`
	Roles   []string     `json:"roles"`
	Status  HealthStatus `json:"status"`
	Checks  CheckResults `json:"checks"`
}

// HealthStatus represents relay health state
type HealthStatus string

const (
	StatusHealthy  HealthStatus = "healthy"
	StatusDegraded HealthStatus = "degraded"
	StatusOffline  HealthStatus = "offline"
)

// CheckResults contains all check results for a relay
type CheckResults struct {
	Metrics *MetricsCheck `json:"metrics"`
	Circuit *CircuitCheck `json:"circuit"`
	HTTP    *HTTPCheck    `json:"http"`
}

// MetricsCheck is the result of metrics endpoint check
type MetricsCheck struct {
	Status         CheckStatus `json:"status"`
	LatencyMs      int64       `json:"latency_ms"`
	Error          string      `json:"error,omitempty"`
	Version        string      `json:"version,omitempty"`
	CircuitsActive int         `json:"circuits_active,omitempty"`
	BytesReceived  int64       `json:"bytes_received,omitempty"`
	BytesSent      int64       `json:"bytes_sent,omitempty"`
}

// CircuitCheck is the result of circuit build test
type CircuitCheck struct {
	Status    CheckStatus `json:"status"`
	LatencyMs int64       `json:"latency_ms"`
	Error     string      `json:"error,omitempty"`
	CircuitID string      `json:"circuit_id,omitempty"`
	Role      string      `json:"role_tested,omitempty"`
}

// HTTPCheck is the result of end-to-end HTTP test
type HTTPCheck struct {
	Status     CheckStatus `json:"status"`
	LatencyMs  int64       `json:"latency_ms"`
	Error      string      `json:"error,omitempty"`
	StatusCode int         `json:"status_code,omitempty"`
	TestSite   string      `json:"test_site"`
}

// CheckStatus represents individual check result
type CheckStatus string

const (
	CheckOK      CheckStatus = "ok"
	CheckFailed  CheckStatus = "failed"
	CheckTimeout CheckStatus = "timeout"
)
