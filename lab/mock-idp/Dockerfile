# TODO: pin @sha256:<digest> — run: docker pull python:3.12.11-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12.11-slim
FROM python:3.12.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] cryptography python-jose[cryptography] python-multipart
COPY server.py .
CMD ["python", "server.py"]
