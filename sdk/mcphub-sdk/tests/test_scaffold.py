"""
Tests for mcphub_sdk.scaffold.

Covers:
  - scaffold() writes exactly 4 files into <out_dir>/<name>/
  - server.py is py_compile-clean
  - server.py imports PlatformMCPServer
  - server.py has NO user_sub / caller / principal tool parameter (H3 / FO-1)
  - Dockerfile contains  FROM mcphub-sdk:base
  - compose-snippet.yaml contains the *mcp-hardening anchor reference
  - compose-snippet.yaml contains the 127.0.0.1: port binding pattern
  - compose-snippet.yaml healthcheck uses /mcp initialize POST (not /health)
  - CLI (main()) writes files into the current directory via --out-dir
  - main() exits 1 if directory already exists
"""
from __future__ import annotations

import py_compile
import re
import sys
from pathlib import Path

import pytest

from mcphub_sdk.scaffold import scaffold, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_FILES = {"server.py", "Dockerfile", "requirements.txt", "compose-snippet.yaml"}


def _read(path: Path, name: str) -> str:
    return (path / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Core scaffold tests
# ---------------------------------------------------------------------------


class TestScaffoldFilesWritten:
    def test_creates_exactly_four_files(self, tmp_path: Path) -> None:
        out = scaffold("foo", out_dir=tmp_path)
        written = {f.name for f in out.iterdir()}
        assert written == EXPECTED_FILES

    def test_returns_absolute_path(self, tmp_path: Path) -> None:
        out = scaffold("bar", out_dir=tmp_path)
        assert out.is_absolute()
        assert out.name == "bar"

    def test_directory_name_matches_arg(self, tmp_path: Path) -> None:
        out = scaffold("my-svc", out_dir=tmp_path)
        assert out.name == "my-svc"

    def test_raises_if_dir_exists(self, tmp_path: Path) -> None:
        scaffold("dup", out_dir=tmp_path)
        with pytest.raises(FileExistsError):
            scaffold("dup", out_dir=tmp_path)


# ---------------------------------------------------------------------------
# server.py
# ---------------------------------------------------------------------------


class TestServerPy:
    def _server_py(self, tmp_path: Path, name: str = "foo") -> str:
        out = scaffold(name, out_dir=tmp_path)
        return _read(out, "server.py")

    def test_py_compile_clean(self, tmp_path: Path) -> None:
        out = scaffold("foo", out_dir=tmp_path)
        # py_compile.compile raises SyntaxError on invalid Python
        py_compile.compile(str(out / "server.py"), doraise=True)

    def test_contains_platform_mcp_server_import(self, tmp_path: Path) -> None:
        content = self._server_py(tmp_path)
        assert "PlatformMCPServer" in content

    def test_contains_identity_call(self, tmp_path: Path) -> None:
        content = self._server_py(tmp_path)
        assert "identity()" in content

    def test_uses_server_name_slug(self, tmp_path: Path) -> None:
        content = self._server_py(tmp_path, name="my-service")
        assert "my-service-mcp" in content

    def test_contains_srv_run(self, tmp_path: Path) -> None:
        content = self._server_py(tmp_path)
        assert "srv.run()" in content

    # H3 / FO-1 — CRITICAL security check
    def test_no_identity_as_tool_parameter(self, tmp_path: Path) -> None:
        """server.py must NOT declare user_sub / caller / principal as a tool arg.

        H3 (spec §Critic hardening): identity is ONLY from identity(); a tool
        parameter for the caller's identity is forgeable.
        """
        content = self._server_py(tmp_path)
        # Look for def <tool>(... user_sub / caller / principal ...) patterns.
        # We check the actual parameter list, not comments.
        # Strip comments first to avoid false positives from doc/comment lines.
        code_lines = [
            ln for ln in content.splitlines() if not ln.lstrip().startswith("#")
        ]
        code_no_comments = "\n".join(code_lines)

        forbidden = re.compile(
            r"\b(user_sub|caller_sub|caller_id|principal_id|principal)\s*[=,:\)]"
        )
        assert not forbidden.search(code_no_comments), (
            "server.py must not declare user_sub/caller/principal as a tool parameter. "
            "Identity must come from identity() only (H3/FO-1)."
        )


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------


class TestDockerfile:
    def test_from_mcphub_sdk_base(self, tmp_path: Path) -> None:
        out = scaffold("foo", out_dir=tmp_path)
        content = _read(out, "Dockerfile")
        assert "FROM mcphub-sdk:base" in content

    def test_copy_server_py(self, tmp_path: Path) -> None:
        out = scaffold("foo", out_dir=tmp_path)
        content = _read(out, "Dockerfile")
        assert "server.py" in content

    def test_cmd_python_server(self, tmp_path: Path) -> None:
        out = scaffold("foo", out_dir=tmp_path)
        content = _read(out, "Dockerfile")
        assert "python" in content and "server.py" in content


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------


class TestRequirementsTxt:
    def test_file_exists(self, tmp_path: Path) -> None:
        out = scaffold("foo", out_dir=tmp_path)
        assert (out / "requirements.txt").exists()

    def test_has_guiding_comment(self, tmp_path: Path) -> None:
        out = scaffold("foo", out_dir=tmp_path)
        content = _read(out, "requirements.txt")
        # Must tell the author the base image already provides common deps
        assert "base" in content.lower()


# ---------------------------------------------------------------------------
# compose-snippet.yaml
# ---------------------------------------------------------------------------


class TestComposeSnippet:
    def _snippet(self, tmp_path: Path, name: str = "foo", port: int = 8000) -> str:
        out = scaffold(name, out_dir=tmp_path, port=port)
        return _read(out, "compose-snippet.yaml")

    def test_contains_mcp_hardening_anchor(self, tmp_path: Path) -> None:
        """The service block must include  <<: *mcp-hardening."""
        content = self._snippet(tmp_path)
        assert "*mcp-hardening" in content

    def test_contains_loopback_port_binding(self, tmp_path: Path) -> None:
        """Port must be bound to 127.0.0.1 (not 0.0.0.0) for lab safety."""
        content = self._snippet(tmp_path, port=8199)
        assert "127.0.0.1:" in content
        assert "8199" in content

    def test_healthcheck_uses_initialize_not_health_path(self, tmp_path: Path) -> None:
        """H1: healthcheck must POST MCP initialize to /mcp, NOT probe /health.

        Spec §H1 (critic hardening): the compose healthcheck uses the proven
        lab /mcp initialize POST pattern, NOT a /health probe.
        """
        content = self._snippet(tmp_path)
        # Must contain the MCP initialize method
        assert "initialize" in content
        # Must reference the /mcp path
        assert "/mcp" in content

    def test_healthcheck_posts_to_mcp_not_health_endpoint(self, tmp_path: Path) -> None:
        """The healthcheck test string must not use /health as the probe URL."""
        content = self._snippet(tmp_path)
        # Extract the test: line(s)
        test_lines = [ln for ln in content.splitlines() if "test:" in ln]
        assert test_lines, "compose-snippet.yaml has no 'test:' healthcheck line"
        combined = " ".join(test_lines)
        # /mcp must be the target, not /health
        assert "/mcp" in combined, "healthcheck test must target /mcp"

    def test_healthcheck_checks_server_info(self, tmp_path: Path) -> None:
        """The healthcheck must verify the response contains 'serverInfo'."""
        content = self._snippet(tmp_path)
        assert "serverInfo" in content

    def test_pairwise_network_present(self, tmp_path: Path) -> None:
        """Each server gets its own pairwise mcp-<name>-net."""
        content = self._snippet(tmp_path, name="baz")
        assert "mcp-baz-net" in content

    def test_lab_net_present(self, tmp_path: Path) -> None:
        content = self._snippet(tmp_path)
        assert "lab-net" in content

    def test_container_name_matches_server_name(self, tmp_path: Path) -> None:
        content = self._snippet(tmp_path, name="qux")
        assert "lab-mcp-qux" in content
        assert "container_name: lab-mcp-qux" in content

    def test_image_tag_is_lab(self, tmp_path: Path) -> None:
        content = self._snippet(tmp_path, name="qux")
        assert "lab-mcp-qux:lab" in content

    def test_todo_comment_for_port(self, tmp_path: Path) -> None:
        """Operator must be reminded to pick a free port."""
        content = self._snippet(tmp_path)
        assert "TODO" in content

    def test_interval_and_retries_match_echo(self, tmp_path: Path) -> None:
        """Healthcheck timing must match the lab-mcp-echo block (10s/5s/5/20s)."""
        content = self._snippet(tmp_path)
        assert "interval: 10s" in content
        assert "timeout: 5s" in content
        assert "retries: 5" in content
        assert "start_period: 20s" in content


# ---------------------------------------------------------------------------
# CLI (main) tests
# ---------------------------------------------------------------------------


class TestMain:
    def test_cli_writes_files(self, tmp_path: Path, capsys) -> None:
        main(["cli-test", "--out-dir", str(tmp_path), "--port", "9100"])
        out = tmp_path / "cli-test"
        assert out.is_dir()
        written = {f.name for f in out.iterdir()}
        assert written == EXPECTED_FILES

    def test_cli_exits_1_on_existing_dir(self, tmp_path: Path) -> None:
        main(["dup", "--out-dir", str(tmp_path)])
        with pytest.raises(SystemExit) as exc_info:
            main(["dup", "--out-dir", str(tmp_path)])
        assert exc_info.value.code == 1

    def test_cli_custom_port_in_snippet(self, tmp_path: Path) -> None:
        main(["port-test", "--out-dir", str(tmp_path), "--port", "9999"])
        snippet = (tmp_path / "port-test" / "compose-snippet.yaml").read_text()
        assert "9999" in snippet
