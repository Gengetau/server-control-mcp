# Changelog

## Unreleased

- Documented `CODING_TOOLS_MCP_ALLOWED_ORIGINS` and verified ChatGPT custom MCP connections (origin `https://chatgpt.com`, redirect host `chatgpt.com`) alongside Claude and Gemini.
- Added RFC 9728 path-aware protected resource metadata (`/.well-known/oauth-protected-resource/mcp`) and `scope="mcp"` advertisement in `WWW-Authenticate` for Gemini Connected Apps compatibility.
- Accepted omitted, origin, or `origin + "/mcp"` `resource` parameters across `/oauth/authorize` and `/oauth/token` while keeping JWT audiences bound to the origin.
- Allowed confidential OAuth clients to authenticate via either `client_secret_post` or `client_secret_basic` (RFC 6749 section 2.3.1), while keeping public PKCE clients strict.
- Added bounded refresh-token lost-rotation recovery scoped exclusively to Google HTTPS OAuth redirect clients (`oauth-redirect*.googleusercontent.com`).
- Added bounded RFC 9112 `Transfer-Encoding: chunked` request body decoding in the OAuth gateway (`1 MiB` on `/mcp`, `8 KiB` on `/oauth/*`, rejecting `Content-Length` + `Transfer-Encoding` conflicts) for HTTP/2-to-HTTP/1.1 reverse proxies, plus legacy `MCP-Protocol-Version` (`2025-03-26`, `2024-11-05`) header compatibility and `OPTIONS` preflight support on new endpoints.

## 0.1.0 — 2026-10-26

- Extracted persistent OAuth gateway from a private Linux deployment.
- Kept the executor as the unchanged coding-tools-mcp 0.3.0 dependency.
- Generalized directed events to an OAuth-client-addressed SQLite outbox.
- Added configurable loopback ports, backend Bearer authentication, safe defaults,
  a process supervisor, non-root container and systemd examples.
- Removed private identities, local service endpoints, production state and credentials.
- Removed the private deployment's legacy access-token migration bypass.
- Added unit/HTTP tests, isolated end-to-end smoke, CI and allowlisted release packaging.
- Events RPCs re-validate the Bearer grant (revocation-aware) in the gateway.
- Release scan reads deployment-specific patterns from an untracked `.release-denylist`.
- Pinned the container base image by digest and added Dependabot configuration.
