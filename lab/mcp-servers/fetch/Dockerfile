# Requires the SDK base image: run `make sdk-base` first.
# Extra deps beyond mcphub-sdk:base's mcp/uvicorn/httpx: the upstream fetch
# server's own HTML→markdown pipeline (readabilipy, markdownify) and
# robots.txt parser (protego) — vendored logic, see server.py docstring.
FROM mcphub-sdk:base
USER root
COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
USER appuser
COPY --chown=appuser:appgroup server.py .
CMD ["python", "server.py"]
