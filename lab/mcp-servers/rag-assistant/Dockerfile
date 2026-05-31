FROM python:3.12-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

COPY requirements.txt .
# Pin transitive deps and verify hashes (supply-chain hardening)
# Generate lockfile with: pip-compile requirements.txt --generate-hashes -o requirements.lock
COPY requirements.lock* ./
RUN if [ -f requirements.lock ]; then \
      pip install --no-cache-dir --require-hashes -r requirements.lock; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi

COPY --chown=appuser:appgroup server.py .

# Only mount docs/ — never mount KB/ (internal security content)
# docker run ... -v ./docs:/app/docs:ro
# SECURITY: KB_DIR env var is intentionally absent. The server does not index KB.
ENV DOCS_DIR=/app/docs \
    MAX_RESULTS=5 \
    SNIPPET_CHARS=400 \
    PORT=8000 \
    HOST=0.0.0.0

USER appuser
EXPOSE 8000

CMD ["python", "server.py"]
