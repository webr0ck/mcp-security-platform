# TODO: pin @sha256:<digest> — run: docker pull python:3.12.11-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim

WORKDIR /app

RUN pip install --no-cache-dir "mcp[cli]>=1.0.0" uvicorn asyncpg httpx starlette

COPY server.py .

ENV HOST=0.0.0.0
ENV PORT=8000

EXPOSE 8000

CMD ["python", "server.py"]
