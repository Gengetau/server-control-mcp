FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
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
