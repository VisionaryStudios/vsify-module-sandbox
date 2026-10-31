"""`scripts/smoke_test.py` launches a BUILT image the way the host does, so it must keep supplying
everything the image's loader requires (issue #1417).

The loader refuses a launch with no approved-bytes digest (`entrypoint_digest_missing`, issue #1310)
and the container exits before READY. This script did not set `VSIFY_SANDBOX_ENTRYPOINT_SHA256`, and
it only runs in the mirror repository after a release tag is cut, so the break reached rc.5 and its
sandbox image was never promoted. These tests need no Docker: they pin the argv each check builds and
that the digest it carries is the one the real loader accepts for the bytes it mounts.
"""

from __future__ import annotations

import pytest
from conftest import load_script_module

from vsify_sandbox import import_closure, module_loader

smoke = load_script_module("smoke_test", "scripts/smoke_test.py")

_ENV = "VSIFY_SANDBOX_ENTRYPOINT_SHA256"
_KINDS = [("script", ""), ("python_module", "modules.acme.entrypoint")]


class _Launched(Exception):
    """Raised by the Popen stand-in once the argv is captured, so no container is ever started."""


def _captured_argv(monkeypatch, check, image, kind, ref):
    seen: list[list[str]] = []

    def _popen(argv, **_kwargs):
        seen.append(list(argv))
        raise _Launched

    monkeypatch.setattr(smoke.subprocess, "Popen", _popen)
    with pytest.raises(_Launched):
        check(image, kind, ref)
    return seen[0]


def _env_values(argv: list[str]) -> dict[str, str]:
    pairs = [argv[i + 1] for i, token in enumerate(argv) if token == "--env"]
    return dict(pair.split("=", 1) for pair in pairs)


@pytest.mark.parametrize("check_name", ["_run_stdio_check", "_run_unix_socket_check"])
@pytest.mark.parametrize("kind, ref", _KINDS)
def test_every_launch_carries_the_digest_of_the_bytes_it_mounts(monkeypatch, check_name, kind, ref):
    argv = _captured_argv(monkeypatch, getattr(smoke, check_name), "img:test", kind, ref)
    env = _env_values(argv)
    assert env.get(_ENV) == smoke._ECHO_SHA256, f"{check_name}/{kind} launches without {_ENV}"
    assert len(env[_ENV]) == 64


@pytest.mark.parametrize("kind, ref", _KINDS)
def test_the_loader_accepts_the_digest_the_smoke_test_supplies(tmp_path, kind, ref):
    target = tmp_path / "entrypoint"
    target.write_text(smoke._ECHO_BODY)
    serve = module_loader._load_entrypoint(
        str(target), kind, ref or "ignored.for.script",
        classify=import_closure._classify_imports,
        validate_ref=import_closure._validate_dotted_ref,
        max_source_bytes=import_closure._MAX_SOURCE_BYTES,
        expected_sha256=smoke._ECHO_SHA256,
    )
    assert serve(b"smoke-test-payload") == b"smoke-test-payload"
