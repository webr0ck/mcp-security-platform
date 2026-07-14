# Requires the SDK base image: run `make sdk-base` first (same as echo/other lab servers).
FROM localhost/mcphub-sdk:base
COPY --chown=appuser:appgroup policy_api_server.py .
COPY --chown=appuser:appgroup server.py .
COPY --chown=appuser:appgroup entrypoint.sh /app/entrypoint.sh
USER root
RUN chmod +x /app/entrypoint.sh
USER appuser
CMD ["/app/entrypoint.sh"]
