import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from crisisweave_platform import PlatformDB
from prometheus_server import build_metrics_server

PEPPER = "test-pepper-value-that-is-long-enough-123"


class HealthyWorksites:
    def health(self):
        return True

    def request(self, method, path, body=None):
        return 200, {"ok": True, "worksites": []}


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = PlatformDB(root / "platform.db", root / "private.db", PEPPER)
        self.server = build_metrics_server(self.db, HealthyWorksites(), "127.0.0.1", 0, 100)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def read(self, path):
        with urlopen(self.base + path, timeout=2) as response:
            return response.status, response.headers, response.read().decode()

    def test_metrics_are_prometheus_text_and_low_cardinality(self):
        self.read("/healthz")
        status, headers, text = self.read("/metrics")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers["Content-Type"])
        self.assertIn("crisisweave_platform_uptime_seconds", text)
        self.assertIn('crisisweave_platform_database_healthy{database="platform"} 1', text)
        self.assertIn("crisisweave_platform_worksites_up 1", text)
        self.assertIn('crisisweave_platform_http_responses_total{status_class="2xx"} 1', text)
        for sensitive_label in ("principal=", "organisation=", "worksite=", "token=", "path="):
            self.assertNotIn(sensitive_label, text)

    def test_metrics_endpoint_does_not_require_application_bearer_token(self):
        status, _, text = self.read("/metrics")
        self.assertEqual(status, 200)
        self.assertNotIn("authentication required", text)


if __name__ == "__main__":
    unittest.main()
