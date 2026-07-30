# Prototype benchmark

The benchmark was run on the development Mac in release mode:

```console
cargo run --release --bin fastpx-bench -- \
  --connections 5000 \
  --concurrency 200
```

| Scenario | CONNECT/s | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| No authentication | 3,756 | 51.5 ms | 58.9 ms | 86.0 ms |
| Simulated two-token NTLM | 3,205 | 60.8 ms | 65.9 ms | 97.5 ms |

The simulated NTLM run uses the real HTTP authentication state machine and
three CONNECT requests on each upstream socket, but substitutes tiny in-process
tokens for native SSPI calls.

These figures are a transport regression baseline, not a direct comparison with
Px. Everything runs over loopback, while Px's published figures use a different
test harness and environment. A defensible performance claim requires both
proxies to be measured on the same Windows workstation, through the same
corporate proxy, against the same destinations.

For the first Windows trial, capture:

- successful CONNECT operations per second
- p50, p95, and p99 establishment latency
- process CPU time and peak working set
- success rate at 50, 100, 250, 500, and 1,000 concurrent clients
- sustained throughput through 100 long-lived tunnels
