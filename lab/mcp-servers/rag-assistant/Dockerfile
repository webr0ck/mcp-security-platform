# TODO: pin @sha256:<digest> — run: docker pull python:3.12.11-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

COPY requirements.txt .
# To add hash-pinned lockfile: pip-compile requirements.txt --generate-hashes -o requirements.lock
# then: COPY requirements.lock . && RUN pip install --no-cache-dir --require-hashes -r requirements.lock
RUN pip install --no-cache-dir -r requirements.txt

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
