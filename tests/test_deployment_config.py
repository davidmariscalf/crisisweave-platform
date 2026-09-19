from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compose_forwards_runtime_security_environment():
    source = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    for name in (
        "CW_ALLOWED_ORIGIN",
        "CW_TOKEN_TTL_HOURS",
        "CW_TRUST_PROXY",
        "CW_MAX_HTTP_WORKERS",
        "CW_HTTP_SOCKET_TIMEOUT",
    ):
        assert f"{name}:" in source


def test_example_environment_documents_proxy_controls():
    source = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "CW_ALLOWED_ORIGIN=" in source
    assert "CW_TRUST_PROXY=false" in source
    assert "CW_MAX_HTTP_WORKERS=64" in source
    assert "CW_HTTP_SOCKET_TIMEOUT=10" in source
