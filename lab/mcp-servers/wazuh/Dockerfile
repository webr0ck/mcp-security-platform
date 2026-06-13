# TODO: pin @sha256:<digest> — run: podman pull python:3.12.11-slim && podman inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

RUN pip install --no-cache-dir \
    mcp==1.9.4 \
    httpx==0.28.1 \
    uvicorn[standard]==0.34.3

COPY --chown=appuser:appgroup server.py /app/server.py

USER appuser

ENV HOST=0.0.0.0
ENV PORT=8000
ENV WAZUH_API_URL=https://wazuh-manager:55000
ENV VERIFY_SSL=false
ENV ALLOW_ACTIVE_RESPONSE=false

EXPOSE 8000

CMD ["python", "server.py"]
