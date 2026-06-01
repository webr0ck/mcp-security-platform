FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir "mcp[cli]>=1.0.0" uvicorn httpx

COPY server.py .

ENV HOST=0.0.0.0
ENV PORT=8000
ENV SERVER_NAME=echo-mcp

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/health')" 2>/dev/null || exit 1

CMD ["python", "server.py"]
