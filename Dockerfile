FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CW_DB=/data/platform.db \
    CW_PRIVATE_DB=/data/private.db \
    CW_HOST=0.0.0.0 \
    CW_PORT=8080

WORKDIR /app
COPY crisisweave_platform.py admin.html /app/
RUN useradd --create-home --uid 10001 crisisweave && mkdir -p /data /feeds && chown -R crisisweave:crisisweave /data /app
USER crisisweave
VOLUME ["/data"]
EXPOSE 8080
CMD ["python", "crisisweave_platform.py", "serve"]
