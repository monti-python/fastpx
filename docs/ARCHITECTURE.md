# Architecture

## Data path

1. A Tokio listener accepts a local client connection.
2. `fastpx` reads one bounded HTTP/1 request head.
3. Non-`CONNECT` requests are rejected; the CONNECT authority is validated as
   an explicit `host:port`.
4. In automatic mode, the destination is resolved locally. Internal addresses
   are connected directly using the selected resolved IP.
5. Other destinations are connected through the configured corporate proxy.
6. The upstream CONNECT request is retried through the proxy's `407`
   authentication exchange.
7. After the direct connection succeeds or the upstream returns a 2xx response,
   `fastpx` returns `200 Connection Established` locally and relays bytes in
   both directions.

The proxy does not terminate TLS and cannot inspect HTTPS payloads.

## Authentication

Every upstream TCP connection gets its own SSPI security context. On Windows,
the context is created with:

- `AcquireCredentialsHandleW` using the current process identity
- the `Negotiate` or `NTLM` security package
- `SECPKG_CRED_OUTBOUND`
- `InitializeSecurityContextW` for each token exchange
- the target name `HTTP/<corporate-proxy-host>`

SSPI tokens remain opaque. They are only base64 encoded into
`Proxy-Authorization` and are never logged.

NTLM is connection-oriented. Once a token-bearing exchange starts, all later
rounds must use the same upstream socket. A tokenless initial `407` may close its
probe socket; `fastpx` safely reconnects before creating and sending the first
client token.

## Resource bounds

- HTTP request and response heads have a configurable size cap.
- A semaphore bounds simultaneous client connections.
- Each relay direction uses one heap-allocated 64 KiB buffer.
- An activity-based idle timeout is shared across both relay directions.
- Authentication has a fixed round limit.

## Current scope

Implemented:

- CONNECT tunnelling
- explicit upstream endpoint
- DNS-aware direct routing for internal destination networks
- configurable additional direct CIDRs and proxy-only mode
- native logged-in-user Windows SSPI
- Negotiate, NTLM, auto selection, and unauthenticated mode
- 407 body draining for Content-Length and chunked framing
- early client-data preservation
- graceful shutdown and structured logs

Not implemented:

- plain HTTP forwarding
- PAC, WPAD, and Windows Internet Options discovery
- upstream failover
- downstream client authentication
- Windows service packaging
- credential-handle caching
- authenticated connection pooling for plain HTTP
