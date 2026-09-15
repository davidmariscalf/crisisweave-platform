FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CW_DB=/data/platform.db \
    CW_PRIVATE_DB=/data/private.db \
    CW_HOST=0.0.0.0 \
    CW_PORT=8080 \
    CW_MAX_HTTP_WORKERS=64 \
    CW_HTTP_SOCKET_TIMEOUT=10

WORKDIR /app
COPY crisisweave_platform.py prometheus_server.py server_runtime.py audit_guard.py maintenance.py admin.html /app/
RUN useradd --create-home --uid 10001 crisisweave && mkdir -p /data /feeds && chown -R crisisweave:crisisweave /data /app
USER crisisweave
VOLUME ["/data"]
EXPOSE 8080
CMD ["sh", "-c", "python audit_guard.py install >/dev/null && exec python prometheus_server.py"]
