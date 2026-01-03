package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-health/internal/checker"
	"github.com/TONresistor/tonnet-health/internal/directory"
	"github.com/TONresistor/tonnet-health/internal/types"
)

var (
	version = "dev"

	// Flags
	directoryURL string
	proxyBinary  string
	testSite     string
	outputJSON   bool
	verbose      bool
	relayFilter  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "tonnet-health",
		Short: "Health checker for Tonnet relay network",
		Long: `Tonnet Health checks the health of all relays in the Tonnet network.

It fetches the relay list from the directory, then for each relay:
  1. Checks the metrics endpoint (:9090)
  2. Builds a circuit through the relay
  3. Makes an HTTP request to verify end-to-end connectivity`,
		RunE: runCheck,
	}

	rootCmd.Flags().StringVar(&directoryURL, "directory", "", "Relay directory URL (default: GitHub)")
	rootCmd.Flags().StringVar(&proxyBinary, "proxy", "../tonnet-proxy/tonnet-proxy", "Path to tonnet-proxy binary")
	rootCmd.Flags().StringVar(&testSite, "test-site", "tonnet-sync-check.ton", "Site to use for HTTP test")
	rootCmd.Flags().BoolVar(&outputJSON, "json", false, "Output JSON format")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVar(&relayFilter, "relay", "", "Check only this relay (by name)")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("tonnet-health %s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runCheck(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Fetch relay directory
	if !outputJSON {
		fmt.Println("Fetching relay directory...")
	}

	dirClient := directory.NewClient(directoryURL)
	dir, err := dirClient.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch directory: %w", err)
	}

	if !outputJSON {
		fmt.Printf("Found %d relays\n\n", len(dir.Relays))
	}

	// Filter relays if specified
	relays := dir.Relays
	if relayFilter != "" {
		var filtered []types.Relay
		for _, r := range relays {
			if r.Name == relayFilter {
				filtered = append(filtered, r)
				break
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("relay not found: %s", relayFilter)
		}
		relays = filtered
	}

	// Check relays
	healthChecker := checker.NewChecker(proxyBinary, testSite, verbose)
	circuitTester := checker.NewCircuitTester(proxyBinary, testSite)

	report := types.HealthReport{
		CheckedAt: time.Now().UTC(),
		Relays:    make([]types.RelayHealth, 0, len(relays)),
	}

	for i, relay := range relays {
		if !outputJSON {
			fmt.Printf("[%d/%d] Checking %s (%s)...\n", i+1, len(relays), relay.Name, relay.Address)
		}

		health := healthChecker.CheckRelay(ctx, relay, dir.Relays)

		// Perform circuit + HTTP test
		if health.Checks.Metrics != nil && health.Checks.Metrics.Status == types.CheckOK {
			result, err := testCircuitWithRelay(ctx, circuitTester, relay, dir.Relays)
			if err != nil {
				health.Checks.Circuit = &types.CircuitCheck{
					Status: types.CheckFailed,
					Error:  err.Error(),
				}
				health.Checks.HTTP = &types.HTTPCheck{
					Status:   types.CheckFailed,
					Error:    err.Error(),
					TestSite: testSite,
				}
			} else {
				health.Checks.Circuit = &types.CircuitCheck{
					Status:    types.CheckOK,
					LatencyMs: result.CircuitLatencyMs,
					CircuitID: result.CircuitID,
				}
				health.Checks.HTTP = &types.HTTPCheck{
					Status:     types.CheckOK,
					LatencyMs:  result.HTTPLatencyMs,
					StatusCode: result.HTTPStatusCode,
					TestSite:   testSite,
				}
				if result.HTTPError != "" {
					health.Checks.HTTP.Status = types.CheckFailed
					health.Checks.HTTP.Error = result.HTTPError
				}
			}
		}

		// Update status based on all checks
		health.Status = determineStatus(health.Checks)
		report.Relays = append(report.Relays, health)

		if !outputJSON {
			printRelayStatus(health)
		}
	}

	// Calculate network health
	report.NetworkHealth = calculateNetworkHealth(report.Relays)

	// Output
	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Print summary
	fmt.Println()
	fmt.Println("=== Network Health ===")
	fmt.Printf("Total: %d | Healthy: %d | Degraded: %d | Offline: %d\n",
		report.NetworkHealth.TotalRelays,
		report.NetworkHealth.Healthy,
		report.NetworkHealth.Degraded,
		report.NetworkHealth.Offline,
	)
	fmt.Printf("Score: %.0f%%\n", report.NetworkHealth.Score*100)

	return nil
}

func testCircuitWithRelay(ctx context.Context, ct *checker.CircuitTester, target types.Relay, allRelays []types.Relay) (*checker.CircuitResult, error) {
	var entry, middle, exit *types.Relay

	// Find suitable relays for each position
	role := selectRole(target)

	for i := range allRelays {
		r := &allRelays[i]
		if r.Name == target.Name {
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

	// Place target in correct position
	switch role {
	case "entry":
		entry = &target
	case "middle":
		middle = &target
	case "exit":
		exit = &target
	}

	if entry == nil || middle == nil || exit == nil {
		return nil, fmt.Errorf("not enough relays for circuit")
	}

	return ct.TestCircuit(ctx, entry, middle, exit)
}

func selectRole(relay types.Relay) string {
	for _, role := range []string{"middle", "entry", "exit"} {
		if hasRole(relay.Roles, role) {
			return role
		}
	}
	return "middle"
}

func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func determineStatus(checks types.CheckResults) types.HealthStatus {
	if checks.Metrics == nil || checks.Metrics.Status != types.CheckOK {
		return types.StatusOffline
	}
	if checks.Circuit == nil || checks.Circuit.Status != types.CheckOK {
		return types.StatusDegraded
	}
	if checks.HTTP == nil || checks.HTTP.Status != types.CheckOK {
		return types.StatusDegraded
	}
	return types.StatusHealthy
}

func calculateNetworkHealth(relays []types.RelayHealth) types.NetworkHealth {
	health := types.NetworkHealth{
		TotalRelays: len(relays),
	}

	for _, r := range relays {
		switch r.Status {
		case types.StatusHealthy:
			health.Healthy++
		case types.StatusDegraded:
			health.Degraded++
		case types.StatusOffline:
			health.Offline++
		}
	}

	if health.TotalRelays > 0 {
		health.Score = float64(health.Healthy) / float64(health.TotalRelays)
	}

	return health
}

func printRelayStatus(health types.RelayHealth) {
	var statusIcon string
	switch health.Status {
	case types.StatusHealthy:
		statusIcon = "[OK]"
	case types.StatusDegraded:
		statusIcon = "[WARN]"
	case types.StatusOffline:
		statusIcon = "[FAIL]"
	}

	fmt.Printf("  %s %s\n", statusIcon, health.Name)

	if health.Checks.Metrics != nil {
		if health.Checks.Metrics.Status == types.CheckOK {
			fmt.Printf("      Metrics: OK (%dms) - v%s, %d circuits\n",
				health.Checks.Metrics.LatencyMs,
				health.Checks.Metrics.Version,
				health.Checks.Metrics.CircuitsActive,
			)
		} else {
			fmt.Printf("      Metrics: FAIL - %s\n", health.Checks.Metrics.Error)
		}
	}

	if health.Checks.Circuit != nil {
		if health.Checks.Circuit.Status == types.CheckOK {
			fmt.Printf("      Circuit: OK (%dms) - %s\n",
				health.Checks.Circuit.LatencyMs,
				health.Checks.Circuit.CircuitID,
			)
		} else {
			fmt.Printf("      Circuit: FAIL - %s\n", health.Checks.Circuit.Error)
		}
	}

	if health.Checks.HTTP != nil {
		if health.Checks.HTTP.Status == types.CheckOK {
			fmt.Printf("      HTTP: OK (%dms) - %d %s\n",
				health.Checks.HTTP.LatencyMs,
				health.Checks.HTTP.StatusCode,
				health.Checks.HTTP.TestSite,
			)
		} else {
			fmt.Printf("      HTTP: FAIL - %s\n", health.Checks.HTTP.Error)
		}
	}

	fmt.Println()
}
