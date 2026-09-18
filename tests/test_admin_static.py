from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AdminConsoleStaticTests(unittest.TestCase):
    def read_admin(self):
        return (ROOT / "admin.html").read_text(encoding="utf-8")

    def test_tokens_remain_memory_only(self):
        html = self.read_admin()
        self.assertIn("let auth=''", html)
        self.assertNotIn("localStorage", html)
        self.assertNotIn("sessionStorage", html)
        self.assertNotIn("document.cookie", html)

    def test_operational_actions_use_authenticated_gateway(self):
        html = self.read_admin()
        self.assertIn("Authorization='Bearer '+auth", html)
        self.assertIn("/api/v1/worksites/", html)
        self.assertIn("/assign", html)
        self.assertIn("/release", html)
        self.assertIn("/transition", html)
        self.assertIn("['admin','coordinator'].includes(principal.role)", html)

    def test_dynamic_operational_values_are_escaped(self):
        html = self.read_admin()
        self.assertIn("const esc=value=>", html)
        self.assertIn("${esc(w.title||w.id||'Worksite')}", html)
        self.assertIn("${esc(w.area||'Area not specified')}", html)
        self.assertIn("${esc(x.action)}", html)
        self.assertIn("${esc(x.target||'')}", html)

    def test_state_actions_match_server_workflow(self):
        html = self.read_admin()
        self.assertIn("requested:['triaged','cancelled']", html)
        self.assertIn("triaged:['ready','cancelled']", html)
        self.assertIn("assigned:['in_progress','cancelled']", html)
        self.assertIn("in_progress:['completed','cancelled']", html)


if __name__ == "__main__":
    unittest.main()
