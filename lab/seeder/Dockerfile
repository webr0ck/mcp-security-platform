# TODO: pin @sha256:<digest> — run: docker pull python:3.12.11-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim
WORKDIR /app
RUN pip install --no-cache-dir httpx asyncpg sqlalchemy[asyncio] aiofiles python-dotenv hvac
COPY seed.py .
COPY sql/ sql/
CMD ["python", "seed.py"]
