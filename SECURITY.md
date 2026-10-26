# Security model

This is a single-operator remote execution service. An authenticated OAuth client
can invoke the same executor catalog as the operator. OAuth clients are NOT
separate OS users or separate workspaces. Do not host mutually untrusted tenants.

Both listeners bind 127.0.0.1. Publish only the gateway through an authenticated
HTTPS ingress/reverse proxy. The executor additionally requires a random per-start
Bearer token; gateway credentials are excluded from its process environment.
The gateway state directory must be outside the executor workspace. Keep `.env`
outside that workspace too. Local filesystem permissions remain important.

`safe` is the default upstream command permission mode; it is not a universal
container or kernel sandbox. Inspect `server_info` / `check_exec_environment` for
actual enforcement. In particular, do not interpret OAuth authentication, command
heuristics, or a loopback bind as kernel-level isolation. Use a dedicated ordinary
OS account or the example container. Do not mount the Docker socket or host root.
`trusted`/`dangerous` explicitly broaden execution policy. The service does not
impersonate read-only tools or override their annotations.

Gateway OAuth uses one operator password, PKCE and persistent client registrations.
Every issued access token has a revocable grant. Refresh tokens rotate; replay
revokes the family, including its access tokens and event subscriptions on their
next delivery check. Concurrent use of one refresh token therefore revokes the
grant. Restart preserves state. Rotating password or signing key revokes grants.
The public origin is immutable for a given state DB. Refresh TTL is 90 days;
access TTL defaults to one hour in generated configuration.

Events are experimental and disabled by default. The exact OAuth client ID is the
recipient; no broadcast or user-supplied identity override exists. Only id/kind/time
metadata is delivered. Signing secrets necessarily remain in the private subscription
DB (0600), with directory permissions 0700 under the supervisor. DNS resolves only
to public addresses; each connection pins the validated address and verifies TLS
for the original hostname. Redirects are not followed. Maximum 16 subscriptions,
seven-day TTL cap, 50 events per poll, 30-second worker interval. Delivery can be
repeated after a crash: receivers must deduplicate eventId. The worker is one
process only; do not run multiple gateway workers sharing the same subscription DB.
Delivery never acknowledges or completes business tasks.

Trusted upstream: command execution, file access, path confinement and permission
modes are implemented by the third-party dependency `coding-tools-mcp==0.3.0`
(https://github.com/xyTom/coding-tools-mcp), installed unmodified and pinned. Its
security properties are inherited, not re-implemented here; review it and re-run the
test suite before changing the pin.

Operational limits: no built-in login/DCR rate limiting, no automated state cleanup
or quotas for the local outbox, and no hardened multi-tenant admission layer.
Apply ingress rate limits before exposing the service on a public URL. Monitor
private state disk usage and back it up without publishing it. Outbox rows must
not be deleted/resequenced while active subscriptions depend on their cursors.
No public deployment or independent security audit is claimed for this extracted
version. Report vulnerabilities privately to the repository maintainer; do not
post credentials or reproduction against somebody else's server.
