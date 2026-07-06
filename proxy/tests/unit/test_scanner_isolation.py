"""
Unit tests — proxy image has no scanner binaries (CR-14 / WP-B1).

Before this change, proxy/Dockerfile installed git/trufflehog/syft/semgrep
and proxy/pyproject.toml depended on pip-audit, because clone + scanner
execution ran inside the proxy container. That execution has moved to the
isolated scanner-worker service; these tests pin down that the proxy build
inputs no longer pull in any scanner binary, so a future change can't
silently regress the isolation this fix bought.

Run: pytest proxy/tests/unit/test_scanner_isolation.py -v
"""
from __future__ import annotations

from pathlib import Path

# parents[0]=unit, parents[1]=tests, parents[2]=proxy, parents[3]=mcp-security-platform
_REPO_ROOT = Path(__file__).parents[3]
_PROXY_DOCKERFILE = _REPO_ROOT / "proxy" / "Dockerfile"
_PROXY_PYPROJECT = _REPO_ROOT / "proxy" / "pyproject.toml"
_WORKER_DOCKERFILE = _REPO_ROOT / "scanner_worker" / "Dockerfile"

_SCANNER_BINARY_MARKERS = ("trufflehog", "semgrep", "syft", "pip-audit")


def _non_comment_lines(path: Path) -> str:
    """Strip full-line `#` comments so prose explaining the removal (which
    necessarily names the removed tools) doesn't trip a substring check."""
    return "\n".join(
        line for line in path.read_text().lower().splitlines()
        if not line.strip().startswith("#")
    )


def test_proxy_dockerfile_installs_no_scanner_binaries():
    content = _non_comment_lines(_PROXY_DOCKERFILE)
    for marker in _SCANNER_BINARY_MARKERS:
        assert marker not in content, (
            f"proxy/Dockerfile still references {marker!r} outside a comment — scanner "
            "execution must live only in scanner_worker/Dockerfile (CR-14)"
        )


def test_proxy_dockerfile_no_longer_installs_git():
    """The proxy no longer clones repos itself; git belongs to the worker only."""
    content = _PROXY_DOCKERFILE.read_text()
    # A loose but sufficient check: no apt-get install line names git as a package.
    assert "    git \\" not in content and "\n    git\n" not in content


def test_proxy_pyproject_has_no_pip_audit_dependency():
    content = _PROXY_PYPROJECT.read_text().lower()
    assert '"pip-audit' not in content, (
        "proxy/pyproject.toml still depends on pip-audit — dependency-CVE "
        "execution must live only in scanner_worker/requirements.txt (CR-14)"
    )


def test_scanner_worker_dockerfile_has_the_scanner_binaries_instead():
    content = _WORKER_DOCKERFILE.read_text().lower()
    for marker in ("trufflehog", "semgrep", "syft", "git"):
        assert marker in content, f"scanner_worker/Dockerfile is missing {marker!r}"
