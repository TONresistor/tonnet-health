# tonnet-health

> ⚠️ **Archived.** TONNET has migrated from a custom relay stack ([`tonnet-relay`](https://github.com/TONresistor/tonnet-relay)) to TON's native ADNL tunnel ([`adnl-tunnel`](https://github.com/ton-blockchain/adnl-tunnel)). This health checker is no longer maintained.

Health checker for TONNET relay network.

## What it does

- Fetches relay list from [tonnet-directory](https://github.com/TONresistor/tonnet-directory)
- Tests each relay:
  - **Metrics** - Prometheus endpoint (port 9090)
  - **Circuit** - Build a 3-hop circuit through the relay
  - **HTTP** - Request to `tonnet-sync-check.ton` through the circuit
- Outputs JSON health report
- Runs automatically every 5 minutes via GitHub Actions

## Usage

```bash
# Build
go build -o tonnet-health ./cmd

# Run (requires tonnet-proxy binary)
./tonnet-health --proxy ./tonnet-proxy --json
```

## Output

```json
{
  "network_health": {
    "total_relays": 5,
    "healthy": 5,
    "degraded": 0,
    "offline": 0,
    "score": 1
  },
  "relays": [...]
}
```

## License

MIT
