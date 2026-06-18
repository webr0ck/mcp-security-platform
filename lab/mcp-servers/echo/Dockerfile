# Requires the SDK base image: run `make sdk-base` first.
# The base image ships mcp/uvicorn/httpx + mcphub_sdk, the appuser/appgroup,
# WORKDIR /app, and HOST/PORT defaults — echo needs no extra deps.
FROM mcphub-sdk:base
COPY --chown=appuser:appgroup server.py .
CMD ["python", "server.py"]
