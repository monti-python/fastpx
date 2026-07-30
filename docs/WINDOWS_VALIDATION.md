# Windows validation

The Windows-specific code is compile-checked from macOS against
`x86_64-pc-windows-msvc`. A real Windows machine joined to the company domain is
still required to execute SSPI and test the corporate proxy.

## Build and smoke test

From a Visual Studio Developer PowerShell:

```powershell
cargo build --release
.\target\release\fastpx.exe `
  --upstream proxy.company.example:8080 `
  --auth ntlm `
  --log fastpx=debug
```

In a second terminal:

```powershell
curl.exe --proxy http://127.0.0.1:3128 `
  --head https://www.microsoft.com/
```

Also test `--auth auto` and `--auth negotiate`. Auto mode should prefer
Negotiate when the proxy advertises it and fall back to NTLM otherwise.

## Checks

1. Confirm the process runs as the interactive domain user. A Windows service
   running under Local System will use a different security identity.
2. Confirm the proxy hostname, rather than an alias or IP address, is configured
   when testing Negotiate. The target SPN is `HTTP/<proxy-host>`.
3. Verify authentication tokens never appear in logs.
4. Exercise proxies that return a body with `407`, proxies that close the first
   unauthenticated socket, and long-lived CONNECT tunnels.
5. Confirm an internal hostname resolves locally and bypasses the upstream
   proxy, while a public hostname still uses it.
6. Confirm `--routing proxy-only` disables destination DNS-based bypass.
7. Compare Px and fastpx from the same machine and avoid mixing cold DNS,
   different destinations, or different corporate-network paths.

## Expected gaps

Applications issuing ordinary absolute-form HTTP requests will receive
`405 CONNECT Required`. PAC/WPAD discovery is not available yet, so pass the
corporate proxy explicitly.
