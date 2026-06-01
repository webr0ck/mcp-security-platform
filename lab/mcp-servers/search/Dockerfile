FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir "mcp[cli]>=1.0.0" uvicorn

COPY server.py .

ENV HOST=0.0.0.0
ENV PORT=8000

EXPOSE 8000

CMD ["python", "server.py"]
