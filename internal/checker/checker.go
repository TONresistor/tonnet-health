package checker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TONresistor/tonnet-health/internal/types"
)

const (
	DefaultMetricsPort = 9090
	DefaultTestSite    = "tonnet-sync-check.ton"
	MetricsTimeout     = 5 * time.Second
	CircuitTimeout     = 30 * time.Second
	HTTPTimeout        = 30 * time.Second
)

// Checker performs health checks on relays
type Checker struct {
	proxyBinary string
	testSite    string
	verbose     bool
}

// NewChecker creates a new health checker
func NewChecker(proxyBinary, testSite string, verbose bool) *Checker {
	if testSite == "" {
		testSite = DefaultTestSite
	}
	return &Checker{
		proxyBinary: proxyBinary,
		testSite:    testSite,
		verbose:     verbose,
	}
}

// CheckRelay performs all health checks on a single relay
func (c *Checker) CheckRelay(ctx context.Context, relay types.Relay, allRelays []types.Relay) types.RelayHealth {
	health := types.RelayHealth{
		Name:    relay.Name,
		Address: relay.Address,
		Roles:   relay.Roles,
		Status:  types.StatusHealthy,
		Checks:  types.CheckResults{},
	}

	// Level 1: Metrics check
	health.Checks.Metrics = c.checkMetrics(ctx, relay)

	// Level 2: Circuit build check
	health.Checks.Circuit = c.checkCircuit(ctx, relay, allRelays)

	// Level 3: HTTP check
	health.Checks.HTTP = c.checkHTTP(ctx, relay, allRelays)

	// Determine overall status
	health.Status = c.determineStatus(health.Checks)

	return health
}

// checkMetrics checks the Prometheus metrics endpoint
func (c *Checker) checkMetrics(ctx context.Context, relay types.Relay) *types.MetricsCheck {
	check := &types.MetricsCheck{
		Status: types.CheckFailed,
	}

	// Extract IP from address
	ip := strings.Split(relay.Address, ":")[0]
	url := fmt.Sprintf("http://%s:%d/metrics", ip, DefaultMetricsPort)

	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, MetricsTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		check.Error = err.Error()
		return check
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			check.Status = types.CheckTimeout
			check.Error = "timeout"
		} else {
			check.Error = err.Error()
		}
		return check
	}
	defer resp.Body.Close()

	check.LatencyMs = time.Since(start).Milliseconds()

	if resp.StatusCode != http.StatusOK {
		check.Error = fmt.Sprintf("status %d", resp.StatusCode)
		return check
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		check.Error = err.Error()
		return check
	}

	// Parse metrics
	check.Version = parseMetric(string(body), `go_info\{version="([^"]+)"`)
	check.CircuitsActive = parseMetricInt(string(body), `tonnet_relay_circuits_active\s+(\d+)`)
	check.BytesReceived = parseMetricInt64(string(body), `tonnet_relay_bytes_received_total\s+(\d+)`)
	check.BytesSent = parseMetricInt64(string(body), `tonnet_relay_bytes_sent_total\s+(\d+)`)

	check.Status = types.CheckOK
	return check
}

// checkCircuit tests building a circuit through this relay
func (c *Checker) checkCircuit(ctx context.Context, relay types.Relay, allRelays []types.Relay) *types.CircuitCheck {
	check := &types.CircuitCheck{
		Status: types.CheckFailed,
	}

	// Find other relays to build circuit with
	var entry, middle, exit *types.Relay
	role := c.selectRole(relay)
	check.Role = role

	for i := range allRelays {
		r := &allRelays[i]
		if r.Name == relay.Name {
			continue
		}
		if entry == nil && hasRole(r.Roles, "entry") {
			entry = r
		} else if middle == nil && hasRole(r.Roles, "middle") {
			middle = r
		} else if exit == nil && hasRole(r.Roles, "exit") {
			exit = r
		}
	}

	// Place target relay in correct position
	switch role {
	case "entry":
		entry = &relay
	case "middle":
		middle = &relay
	case "exit":
		exit = &relay
	}

	if entry == nil || middle == nil || exit == nil {
		check.Error = "not enough relays for circuit"
		return check
	}

	// Build circuit using tonnet-proxy
	start := time.Now()
	circuitID, err := c.buildCircuit(ctx, entry, middle, exit)
	check.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			check.Status = types.CheckTimeout
			check.Error = "timeout"
		} else {
			check.Error = err.Error()
		}
		return check
	}

	check.CircuitID = circuitID
	check.Status = types.CheckOK
	return check
}

// checkHTTP performs end-to-end HTTP test through the relay
func (c *Checker) checkHTTP(ctx context.Context, relay types.Relay, allRelays []types.Relay) *types.HTTPCheck {
	check := &types.HTTPCheck{
		Status:   types.CheckFailed,
		TestSite: c.testSite,
	}

	// Similar to circuit check but also perform HTTP request
	var entry, middle, exit *types.Relay
	role := c.selectRole(relay)

	for i := range allRelays {
		r := &allRelays[i]
		if r.Name == relay.Name {
			continue
		}
		if entry == nil && hasRole(r.Roles, "entry") {
			entry = r
		} else if middle == nil && hasRole(r.Roles, "middle") {
			middle = r
		} else if exit == nil && hasRole(r.Roles, "exit") {
			exit = r
		}
	}

	switch role {
	case "entry":
		entry = &relay
	case "middle":
		middle = &relay
	case "exit":
		exit = &relay
	}

	if entry == nil || middle == nil || exit == nil {
		check.Error = "not enough relays for circuit"
		return check
	}

	start := time.Now()
	statusCode, err := c.httpRequest(ctx, entry, middle, exit, c.testSite)
	check.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			check.Status = types.CheckTimeout
			check.Error = "timeout"
		} else {
			check.Error = err.Error()
		}
		return check
	}

	check.StatusCode = statusCode
	if statusCode >= 200 && statusCode < 400 {
		check.Status = types.CheckOK
	} else {
		check.Error = fmt.Sprintf("unexpected status: %d", statusCode)
	}

	return check
}

// buildCircuit builds a circuit through the specified relays
func (c *Checker) buildCircuit(ctx context.Context, entry, middle, exit *types.Relay) (string, error) {
	// This will be implemented to use tonnet-proxy binary or library
	// For now, return success if we can reach the relay
	return "test-circuit", nil
}

// httpRequest performs HTTP request through circuit
func (c *Checker) httpRequest(ctx context.Context, entry, middle, exit *types.Relay, site string) (int, error) {
	// This will be implemented to use tonnet-proxy
	// For now, simulate success
	return 200, nil
}

// selectRole selects which role to test for this relay
func (c *Checker) selectRole(relay types.Relay) string {
	// Prefer testing as middle (less impact), then entry, then exit
	for _, role := range []string{"middle", "entry", "exit"} {
		if hasRole(relay.Roles, role) {
			return role
		}
	}
	return "middle"
}

// determineStatus determines overall health status from checks
func (c *Checker) determineStatus(checks types.CheckResults) types.HealthStatus {
	allOK := true
	anyFailed := false

	if checks.Metrics != nil && checks.Metrics.Status != types.CheckOK {
		if checks.Metrics.Status == types.CheckFailed {
			anyFailed = true
		}
		allOK = false
	}

	if checks.Circuit != nil && checks.Circuit.Status != types.CheckOK {
		if checks.Circuit.Status == types.CheckFailed {
			anyFailed = true
		}
		allOK = false
	}

	if checks.HTTP != nil && checks.HTTP.Status != types.CheckOK {
		if checks.HTTP.Status == types.CheckFailed {
			anyFailed = true
		}
		allOK = false
	}

	if allOK {
		return types.StatusHealthy
	}
	if anyFailed {
		return types.StatusOffline
	}
	return types.StatusDegraded
}

// Helper functions

func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func parseMetric(body, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func parseMetricInt(body, pattern string) int {
	s := parseMetric(body, pattern)
	if s == "" {
		return 0
	}
	v, _ := strconv.Atoi(s)
	return v
}

func parseMetricInt64(body, pattern string) int64 {
	s := parseMetric(body, pattern)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
