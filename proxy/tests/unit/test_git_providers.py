"""PRD-0005 R-2 — git provider URL shapes + SSRF host classification."""
from __future__ import annotations

import pytest
from unittest.mock import patch

from app.services import git_providers as gp


def test_github_url_shapes():
    r = gp._github_re("github.com")
    assert r.match("https://github.com/owner/repo")
    assert r.match("https://github.com/owner/repo.git")
    assert not r.match("https://evil.com/owner/repo")
    assert not r.match("https://github.com/owner")            # missing repo
    assert not r.match("http://github.com/owner/repo")        # not https


def test_bitbucket_datacenter_and_cloud_shapes():
    r = gp._bitbucket_re("bitbucket.corp.example")
    assert r.match("https://bitbucket.corp.example/scm/PROJ/repo.git")   # Data Center /scm
    assert r.match("https://bitbucket.corp.example/PROJ/repos/repo")     # Data Center browser
    assert r.match("https://bitbucket.corp.example/workspace/repo")      # Cloud
    assert not r.match("https://bitbucket.corp.example/onlyonesegment")  # need 2 path segments
    assert not r.match("https://other.example/workspace/repo")          # wrong host
    # NOTE: '/scm/PROJ' legitimately matches the 2-segment Cloud shape
    # (workspace='scm', repo='PROJ') — accepted, not a security concern.


def test_ip_classification():
    assert gp._classify_ip("169.254.169.254") == "block"   # cloud metadata
    assert gp._classify_ip("127.0.0.1") == "block"
    assert gp._classify_ip("::1") == "block"
    assert gp._classify_ip("10.1.2.3") == "private"
    assert gp._classify_ip("192.168.1.1") == "private"
    assert gp._classify_ip("140.82.121.4") == "ok"          # github public
    assert gp._classify_ip("not-an-ip") == "block"          # unparseable -> refuse


def _fake_getaddrinfo(ips):
    return lambda host, port, *a, **k: [(2, 1, 6, "", (ip, 0)) for ip in ips]


def test_validate_host_blocks_metadata_even_with_allow_private():
    with patch("app.services.git_providers.socket.getaddrinfo", _fake_getaddrinfo(["169.254.169.254"])):
        with pytest.raises(gp.GitHostError, match="forbidden"):
            gp.validate_host("metadata.evil", allow_private=True)


def test_validate_host_private_requires_ack():
    with patch("app.services.git_providers.socket.getaddrinfo", _fake_getaddrinfo(["10.0.0.5"])):
        with pytest.raises(gp.GitHostError, match="private"):
            gp.validate_host("bitbucket.corp", allow_private=False)
        # With the ack, the same private host is allowed.
        assert gp.validate_host("bitbucket.corp", allow_private=True) == ["10.0.0.5"]


def test_validate_host_public_ok():
    with patch("app.services.git_providers.socket.getaddrinfo", _fake_getaddrinfo(["140.82.121.4"])):
        assert gp.validate_host("github.com", allow_private=False) == ["140.82.121.4"]


def test_validate_host_dns_failure_is_fail_closed():
    def _boom(*a, **k):
        raise OSError("nxdomain")
    with patch("app.services.git_providers.socket.getaddrinfo", _boom):
        with pytest.raises(gp.GitHostError, match="DNS"):
            gp.validate_host("nope.invalid", allow_private=True)


def test_build_clone_url_injects_and_noops():
    assert gp.build_clone_url("https://github.com/o/r", "bot", "tok") == "https://bot:tok@github.com/o/r"
    assert gp.build_clone_url("https://github.com/o/r", None, None) == "https://github.com/o/r"
