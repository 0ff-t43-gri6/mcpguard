# mcpguard as a shared HTTP gateway.
#   docker build -t mcpguard .
#   docker run -v ./data:/data -p 8766:8766 -e MCPGUARD_TOKEN_CI=... mcpguard
# /data holds mcpguard.toml and everything the gateway writes (audit log, key, pins, state).
# Tool servers started by the gateway run inside this container: add their runtimes (Node,
# uv, ...) in an image built FROM this one, or use remote (HTTP) servers.
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --no-deps -w /wheels .

FROM python:3.13-slim
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels \
    && useradd --create-home --uid 10001 mcpguard && mkdir /data && chown mcpguard /data
USER mcpguard
WORKDIR /data
VOLUME /data
EXPOSE 8766
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD \
    python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8766/healthz', timeout=3).status == 200 else 1)"
ENTRYPOINT ["mcpguard", "-c", "/data/mcpguard.toml"]
# Listening beyond loopback requires at least one [clients.<name>] token in the config.
CMD ["serve", "--host", "0.0.0.0", "--port", "8766"]
