FROM python:3.12.11-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

RUN pip install --no-cache-dir "mcp[cli]>=1.0.0" uvicorn httpx

COPY --chown=appuser:appgroup server.py .

USER appuser

ENV HOST=0.0.0.0
ENV PORT=8000
ENV SERVER_NAME=entra-id-mcp

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/mcp')" 2>/dev/null || exit 1

CMD ["python", "server.py"]
