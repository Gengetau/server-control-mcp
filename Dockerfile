FROM python:3.14-slim@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8
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
