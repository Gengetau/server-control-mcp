# Contributing

Use Python 3.11 or newer on Linux. Install with `python -m pip install -e .`.
Run `python -m unittest discover -s tests -v`, `python scripts/smoke.py`, and
`python scripts/release.py --check-only` before opening a pull request.

Keep the executor unmodified and pinned until its compatibility tests pass with a
new version. Put integration changes in the facade. Never commit live `.env`,
OAuth databases, callback secrets, real hostnames, private logs or deployment archives.
Add regression tests for authorization, delivery or permission-boundary changes.
Contributions are under Apache-2.0. This is an independent integration project,
not an official release of coding-tools-mcp, OpenAI, Anthropic or Tailscale.
