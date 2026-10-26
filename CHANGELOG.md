# Changelog

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
