FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir httpx asyncpg sqlalchemy[asyncio] aiofiles python-dotenv hvac
COPY seed.py .
COPY sql/ sql/
CMD ["python", "seed.py"]
