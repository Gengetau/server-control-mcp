FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 mcp
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir . && mkdir -p /data/state /data/workspace && chown -R mcp:mcp /data
USER 10001:10001
ENV SCM_STATE_DIR=/data/state SCM_WORKSPACE=/data/workspace PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["server-control-mcp"]
CMD ["serve"]
