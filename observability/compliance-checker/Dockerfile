FROM python:3.12-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    cron \
    && rm -rf /var/lib/apt/lists/*

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

# Entrypoint: run checker.py on cron schedule defined by COMPLIANCE_CRON_SCHEDULE env var
ENTRYPOINT ["/bin/sh", "-c", "echo \"${COMPLIANCE_CRON_SCHEDULE} python /app/checker.py\" | crontab - && cron -f"]
