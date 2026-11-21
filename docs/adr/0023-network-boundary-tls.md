# ADR-0023: Network boundary — TLS, bind, local CA, browser and webview rules

- Status: Accepted. Amended by ADR-0034: the Agent API is no longer the only network surface when the `cerberusd` admin API is on; that API shares this listener and its HTTP rules, and the listener then asks every client for a CA-signed certificate.
- Date: 2026-11-16
- Plan reference: 4.3, 4.7, A8
- Related: ADR-0001, ADR-0003, ADR-0016, ADR-0030

## Context

The Agent API is the only network surface. The admin surface is IPC (ADR-0003). The network side must refuse old TLS
and plain HTTP, and must resist local abuse (other users, browsers, DNS rebinding).

## Decision

### Listener
1. Default bind: `127.0.0.1:7373` and `[::1]:7373`. Port is a setting (owner).
2. A non-loopback bind is an owner action. It needs `require_mtls` on every active agent key. The service refuses the
   bind change if any active key lacks mTLS.
3. Only a TLS listener exists. `rustls` server config with protocol versions **TLS 1.3 only**. ALPN `h2`, `http/1.1`.
   A plain HTTP request is not TLS, so the handshake fails and the connection closes. No HTTP listener and no redirect.
4. Timeouts: TLS handshake 10 s, request headers 10 s, request body 30 s, idle keep-alive 60 s.
   At most 256 concurrent connections; more wait in the accept queue. SSE streams have no
   body timeout but end at the request expiry (ADR-0018).
5. Body limits: 16 KiB default; 1 MiB for `POST /v1/credentials` and `POST /v1/sessions` (browser storage state).

### Local CA and certificates (`rcgen`)
1. At vault creation: CA key ECDSA P-256, self-signed, 10 years, `CN = Cerberus Local CA <vault short id>`,
   path length 0, key usage `keyCertSign`, `cRLSign`.
2. The CA private key is sealed with `ca_key` in table `tls_ca`. It exists in plain form only while unlocked.
3. Leaf: ECDSA P-256, 90 days, SAN `localhost`, `127.0.0.1`, `::1`, host name, plus owner-added names. EKU serverAuth.
4. The leaf key is stored in `<app_data_dir>/tls/leaf-key.der` (mode `0600`), **outside** the DB, because TLS must work
   while the vault is locked (health and 423). The leaf certificate is in `tls/leaf-cert.der`.
5. At unlock, if the leaf expires in less than 30 days or its SAN list changed, the CA signs a new leaf.
6. Pin format: `sha256/<base64 of SHA-256 of the CA SubjectPublicKeyInfo>`. The pin survives leaf renewal.
   The UI shows it, and also shows the hex fingerprint of the CA certificate.
7. Export: CA certificate PEM (IPC `tls_export_ca`). Agents use `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
   `REQUESTS_CA_BUNDLE` or the SDK pin.
8. Custom certificate: the owner can load a certificate chain and key (PEM). The key is then sealed in the DB and
   the server needs an unlock before it can serve. The UI states this. Built in FIX9 (DEC-FIX9-1 to 6): the key and chain
   are sealed in the setting `tls_custom`; a renewal never replaces the custom certificate; the owner can go back to the
   local CA. While a custom certificate is served, clients that pin the local CA no longer match: the pin and the
   fingerprint in Settings come from the active chain (the top certificate of the custom chain).

### HTTP rules
1. `Host` must be one of the leaf SAN names (with or without port). Else `403 origin_refused`. This blocks DNS rebinding.
2. A request with an `Origin` header, or `Sec-Fetch-Site` other than `none`, gives `403 origin_refused`.
   Agents are not browsers. No CORS headers are ever sent.
3. Response headers on every response: `Cache-Control: no-store`, `Pragma: no-cache`,
   `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
   `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Request-Id`.
4. Only `application/json` request bodies (`415` otherwise). Unknown JSON fields give `400 invalid_request`.

### Tauri webview
1. CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';
   connect-src ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`.
2. No remote content. No `shell` plugin. Capabilities per window label (`main`, `approval`).
3. Devtools off in release builds (`tauri` feature `devtools` only in debug).
4. Content protection (no screen capture) on secret views is a setting (default on for macOS and Windows; not
   available on Linux, the UI states this).
5. Clipboard: secret copy through IPC `clipboard_copy_secret`; the backend clears the clipboard after 30 s if it still
   holds that value. A revealed secret hides after 15 s.

## Consequences

- A8 passes: TLS 1.2 handshake fails, plain HTTP fails.
- Another local OS user can reach the port but needs a token (threat model S-2).
- A local user with the same UID can read the leaf key file. This user can already read process memory and the
  vault file, so the leaf file adds no new power (accepted risk S-4).

## Alternatives considered

- **Unix socket for agents.** Rejected as the only transport: many agent tools speak HTTPS only. It may come later.
- **Leaf key inside the vault.** Rejected: health and 423 would not work while locked.
