#!/usr/bin/env python3
from __future__ import annotations

import os
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from crisisweave_platform import (
    PlatformDB,
    PlatformHandler,
    RateLimiter,
    SERVER_VERSION,
    WorksiteClient,
    _parse_allowed_origins,
)


class MetricsRegistry:
    """Low-cardinality process metrics only.

    Labels intentionally exclude paths, principals, organisations, worksites,
    tokens, source URLs and query strings.
    """

    def __init__(self):
        self.started = time.monotonic()
        self._lock = threading.Lock()
        self.status_classes = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
        self.authentication_failures = 0
        self.authorisation_denials = 0
        self.rate_limited = 0
        self.server_errors = 0

    def observe(self, status: int) -> None:
        status = int(status)
        bucket = f"{status // 100}xx"
        with self._lock:
            if bucket in self.status_classes:
                self.status_classes[bucket] += 1
            if status == 401:
                self.authentication_failures += 1
            elif status == 403:
                self.authorisation_denials += 1
            elif status == 429:
                self.rate_limited += 1
            if status >= 500:
                self.server_errors += 1

    def render(self, *, db_health: dict, worksites_ok: bool) -> str:
        with self._lock:
            status = dict(self.status_classes)
            authn = self.authentication_failures
            authz = self.authorisation_denials
            limited = self.rate_limited
            errors = self.server_errors
        uptime = max(0.0, time.monotonic() - self.started)
        lines = [
            "# HELP crisisweave_platform_info Static platform build information.",
            "# TYPE crisisweave_platform_info gauge",
            f'crisisweave_platform_info{{version="{SERVER_VERSION}"}} 1',
            "# HELP crisisweave_platform_uptime_seconds Process uptime in seconds.",
            "# TYPE crisisweave_platform_uptime_seconds gauge",
            f"crisisweave_platform_uptime_seconds {uptime:.3f}",
            "# HELP crisisweave_platform_http_responses_total HTTP responses by status class.",
            "# TYPE crisisweave_platform_http_responses_total counter",
        ]
        for bucket in ("2xx", "3xx", "4xx", "5xx"):
            lines.append(f'crisisweave_platform_http_responses_total{{status_class="{bucket}"}} {status[bucket]}')
        lines += [
            "# HELP crisisweave_platform_authentication_failures_total HTTP 401 responses.",
            "# TYPE crisisweave_platform_authentication_failures_total counter",
            f"crisisweave_platform_authentication_failures_total {authn}",
            "# HELP crisisweave_platform_authorisation_denials_total HTTP 403 responses.",
            "# TYPE crisisweave_platform_authorisation_denials_total counter",
            f"crisisweave_platform_authorisation_denials_total {authz}",
            "# HELP crisisweave_platform_rate_limited_total HTTP 429 responses.",
            "# TYPE crisisweave_platform_rate_limited_total counter",
            f"crisisweave_platform_rate_limited_total {limited}",
            "# HELP crisisweave_platform_server_errors_total HTTP 5xx responses.",
            "# TYPE crisisweave_platform_server_errors_total counter",
            f"crisisweave_platform_server_errors_total {errors}",
            "# HELP crisisweave_platform_database_healthy Database health by fixed database role.",
            "# TYPE crisisweave_platform_database_healthy gauge",
            f'crisisweave_platform_database_healthy{{database="platform"}} {1 if db_health.get("platform_db") else 0}',
            f'crisisweave_platform_database_healthy{{database="private"}} {1 if db_health.get("private_db") else 0}',
            "# HELP crisisweave_platform_worksites_up Worksite service health.",
            "# TYPE crisisweave_platform_worksites_up gauge",
            f"crisisweave_platform_worksites_up {1 if worksites_ok else 0}",
        ]
        return "\n".join(lines) + "\n"


class MetricsPlatformHandler(PlatformHandler):
    metrics: MetricsRegistry

    def _send(self, status, payload, headers=None):
        self.metrics.observe(status)
        return super()._send(status, payload, headers)

    def _html(self, text):
        self.metrics.observe(200)
        return super()._html(text)

    def _send_metrics(self):
        text = self.metrics.render(db_health=self.db.health(), worksites_ok=self.worksites.health())
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in self._base_headers().items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path == "/metrics":
            return self._send_metrics()
        return super().do_GET()


def build_metrics_server(
    db, worksites, host="127.0.0.1", port=8080, rate_limit=120,
    allowed_origin=None, verified_feed=None, alerts_feed=None, admin_html=None,
):
    handler = type("BoundMetricsPlatformHandler", (MetricsPlatformHandler,), {})
    handler.db = db
    handler.worksites = worksites
    handler.limiter = RateLimiter(rate_limit)
    handler.allowed_origins = _parse_allowed_origins(allowed_origin)
    handler.verified_feed = verified_feed
    handler.alerts_feed = alerts_feed
    handler.admin_html = admin_html
    handler.metrics = MetricsRegistry()
    return ThreadingHTTPServer((host, int(port)), handler)


def main() -> int:
    pepper = os.getenv("CW_TOKEN_PEPPER", "")
    db = PlatformDB(os.getenv("CW_DB", "./data/platform.db"), os.getenv("CW_PRIVATE_DB", "./data/private.db"), pepper)
    worksites = WorksiteClient(
        os.getenv("CW_WORKSITES_URL", "http://127.0.0.1:8787"),
        os.getenv("CW_WORKSITES_TOKEN") or None,
    )
    admin = Path(__file__).with_name("admin.html")
    server = build_metrics_server(
        db,
        worksites,
        os.getenv("CW_HOST", "127.0.0.1"),
        int(os.getenv("CW_PORT", "8080")),
        int(os.getenv("CW_RATE_LIMIT_PER_MINUTE", "120")),
        os.getenv("CW_ALLOWED_ORIGIN") or None,
        os.getenv("CW_VERIFIED_FEED") or None,
        os.getenv("CW_ALERTS_FEED") or None,
        admin.read_text(encoding="utf-8") if admin.is_file() else None,
    )
    print(f"CrisisWeave instrumented platform listening on http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
