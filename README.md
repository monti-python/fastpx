# fastpx

[![CI](https://github.com/monti-python/fastpx/actions/workflows/ci.yml/badge.svg)](https://github.com/monti-python/fastpx/actions/workflows/ci.yml)

`fastpx` is a Windows-first local HTTP CONNECT proxy that authenticates to an
upstream corporate proxy with the logged-in user's native SSPI credentials.

This repository currently contains an early prototype. Its intentionally narrow
scope is:

- HTTP `CONNECT` tunnelling
- explicit upstream proxy configuration
- `Negotiate` and `NTLM` through native Windows SSPI
- DNS-aware automatic direct routing for internal destinations
- fully asynchronous socket I/O
- bounded HTTP header parsing
- optional tunnel idle timeout

Plain HTTP forwarding, PAC/WPAD discovery, multiple upstreams, and Windows
service packaging are not implemented yet.

## Download

Every GitHub Actions run produces a `fastpx-win-x64` artifact containing the
executable, README, license, and SHA-256 checksum. Version tags such as `v0.2.0`
publish the same ZIP as a permanent [GitHub
Release](https://github.com/monti-python/fastpx/releases).

GitHub Packages only accepts supported package-registry formats rather than
arbitrary native executables, so release ZIPs are the canonical distribution
channel.

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

### Automatic internal routing

Automatic routing is enabled by default. Before opening a tunnel, fastpx
resolves the destination with the operating system's DNS resolver. Addresses in
loopback, RFC 1918 private, IPv4/IPv6 link-local, IPv6 unique-local, and
100.64.0.0/10 networks are connected directly. Other destinations, including
names that cannot be resolved locally, are sent through the authenticated
upstream proxy.

This makes internal sites work without maintaining `NO_PROXY`. If the company
uses public address space internally, add its networks explicitly:

```console
fastpx --upstream proxy.company.example:8080 \
  --direct-cidr 203.0.113.0/24 \
  --direct-cidr 2001:db8:1234::/48
```

To send every destination through the upstream proxy as in v0.1:

```console
fastpx --upstream proxy.company.example:8080 --routing proxy-only
```

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

Automatic routing intentionally does not try a direct connection to ordinary
public addresses. This prevents fastpx from silently bypassing company egress
policy. A destination selected for direct routing is connected by its resolved
IP rather than resolving the hostname a second time.
