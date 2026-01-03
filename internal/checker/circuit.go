package checker

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/TONresistor/tonnet-health/internal/types"
)

// CircuitTester tests circuits using tonnet-proxy binary
type CircuitTester struct {
	proxyBinary string
	testSite    string
	listenPort  int
}

// NewCircuitTester creates a new circuit tester
func NewCircuitTester(proxyBinary, testSite string) *CircuitTester {
	return &CircuitTester{
		proxyBinary: proxyBinary,
		testSite:    testSite,
		listenPort:  18090,
	}
}

// TestCircuit tests building a circuit and making an HTTP request
func (ct *CircuitTester) TestCircuit(ctx context.Context, entry, middle, exit *types.Relay) (*CircuitResult, error) {
	result := &CircuitResult{}
	start := time.Now()

	// Build relay arguments
	relay1 := fmt.Sprintf("%s,%s", entry.Address, entry.PubKey)
	relay2 := fmt.Sprintf("%s,%s", middle.Address, middle.PubKey)
	relay3 := fmt.Sprintf("%s,%s", exit.Address, exit.PubKey)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	// Start tonnet-proxy in background
	listenAddr := fmt.Sprintf(":%d", ct.listenPort)
	ct.listenPort++ // Increment for next test

	cmd := exec.CommandContext(ctx, ct.proxyBinary,
		"--relay1", relay1,
		"--relay2", relay2,
		"--relay3", relay3,
		"--listen", listenAddr,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}

	// Ensure cleanup
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait for circuit to be ready
	circuitReady := make(chan string, 1)
	circuitError := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Circuit ready") {
				// Extract circuit ID
				re := regexp.MustCompile(`\[([a-f0-9]+)\]`)
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 {
					circuitReady <- matches[1]
					return
				}
				circuitReady <- "unknown"
				return
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "error") || strings.Contains(line, "failed") {
				circuitError <- fmt.Errorf(line)
				return
			}
		}
	}()

	// Wait for circuit or error
	select {
	case circuitID := <-circuitReady:
		result.CircuitID = circuitID
		result.CircuitLatencyMs = time.Since(start).Milliseconds()
	case err := <-circuitError:
		return nil, err
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("circuit build timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Now make HTTP request through the proxy
	httpStart := time.Now()
	statusCode, err := ct.makeHTTPRequest(ctx, listenAddr, ct.testSite)
	result.HTTPLatencyMs = time.Since(httpStart).Milliseconds()

	if err != nil {
		result.HTTPError = err.Error()
	} else {
		result.HTTPStatusCode = statusCode
	}

	result.TotalLatencyMs = time.Since(start).Milliseconds()

	return result, nil
}

// makeHTTPRequest makes an HTTP request through the proxy
func (ct *CircuitTester) makeHTTPRequest(ctx context.Context, proxyAddr, site string) (int, error) {
	// Use curl for simplicity
	url := fmt.Sprintf("http://%s/", site)
	proxyURL := fmt.Sprintf("http://localhost%s", proxyAddr)

	cmd := exec.CommandContext(ctx, "curl",
		"-s",
		"-o", "/dev/null",
		"-w", "%{http_code}",
		"--proxy", proxyURL,
		"--max-time", "20",
		url,
	)

	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	var statusCode int
	fmt.Sscanf(string(output), "%d", &statusCode)

	return statusCode, nil
}

// CircuitResult contains the results of a circuit test
type CircuitResult struct {
	CircuitID        string
	CircuitLatencyMs int64
	HTTPStatusCode   int
	HTTPLatencyMs    int64
	HTTPError        string
	TotalLatencyMs   int64
}
