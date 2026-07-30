# fastpx

`fastpx` is a Windows-first local HTTP CONNECT proxy that authenticates to an
upstream corporate proxy with the logged-in user's native SSPI credentials.

This repository currently contains an early prototype. Its intentionally narrow
scope is:

- HTTP `CONNECT` tunnelling
- explicit upstream proxy configuration
- `Negotiate` and `NTLM` through native Windows SSPI
- fully asynchronous socket I/O
- bounded HTTP header parsing
- optional tunnel idle timeout

Plain HTTP forwarding, PAC/WPAD discovery, multiple upstreams, and Windows
service packaging are not implemented yet.

## Build

```console
cargo build --release
```

## Run

```console
fastpx --upstream proxy.company.example:8080
```

The proxy listens on `127.0.0.1:3128` by default. Configure applications with:

```text
HTTPS_PROXY=http://127.0.0.1:3128
```

Do not set `HTTP_PROXY` yet: this prototype intentionally supports CONNECT
tunnels but not ordinary plain-HTTP forwarding.

Authentication defaults to `auto`, which prefers `Negotiate` and falls back to
`NTLM` according to the upstream proxy's `Proxy-Authenticate` headers:

```console
fastpx --upstream proxy.company.example:8080 --auth ntlm
```

On non-Windows platforms, only `--auth none` is available. This exists so the
transport and protocol state machine can be developed and benchmarked without a
Windows host.

## Test and benchmark

```console
cargo test --all-targets
cargo run --release --bin fastpx-bench -- \
  --connections 5000 \
  --concurrency 200 \
  --mock-ntlm
```

The included benchmark measures loopback CONNECT establishment and a small echo
through each tunnel. It deliberately excludes network latency and native SSPI,
so use it for regression testing rather than as a prediction of corporate-proxy
performance.

See [the architecture](docs/ARCHITECTURE.md), [prototype benchmark
results](docs/BENCHMARKS.md), and [the Windows validation
checklist](docs/WINDOWS_VALIDATION.md) for more detail.

## Security

The listener defaults to loopback. Exposing it on another interface can allow
other machines to use your Windows identity through the corporate proxy. Do not
change `--listen` to a non-loopback address without adding downstream client
authentication and access controls.
