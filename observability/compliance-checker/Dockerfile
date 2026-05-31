FROM python:3.12-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# No system cron — it requires root to write /var/spool/cron/.
# The entrypoint.py runs checker.py on schedule using Python sleep.
RUN pip install --no-cache-dir \
    asyncpg==0.30.0 \
    sqlalchemy==2.0.36 \
    boto3==1.35.0 \
    pydantic==2.9.0 \
    pydantic-settings==2.5.0 \
    structlog==24.4.0 \
    httpx==0.27.0

COPY --chown=appuser:appgroup . /app/

USER appuser

# entrypoint.py reads COMPLIANCE_CHECK_INTERVAL_SECONDS (default 86400 = 24h)
# and runs checker.py on that cadence. No cron, no root, no /var/spool writes.
CMD ["python", "/app/entrypoint.py"]
