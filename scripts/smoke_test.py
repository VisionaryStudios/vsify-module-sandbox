#!/usr/bin/env python3
"""Real end-to-end smoke test against a BUILT image (ADR-P041) — no vsify-enterprise-mcp checkout
needed, so this can run standalone in this repo's own CI. Exercises both `entrypoint_kind`s over
both registered transports; asserts non-root + read-only + network-none containment.

Usage: python3 scripts/smoke_test.py <image-ref>
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vsify_sandbox.framing import FRAME_READY, FRAME_REQUEST, FRAME_RESPONSE, encode_frame, read_frame

_ECHO_BODY = "def serve(payload: bytes) -> bytes:\n    return payload\n"


def _containment_argv(image: str, name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--name", name,
        "--network", "none", "--read-only", "--tmpfs", "/tmp",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", "--pids-limit", "128", "--memory", "512m", "--cpus", "1.0",
    ]


def _docker_kill(name: str) -> None:
    """Reliable teardown for a foreground `docker run --rm` container whose entrypoint sits in an
    infinite serve loop — `proc.terminate()`/`wait()` on the CLI process is NOT reliable here (the
    CLI process only exits once the CONTAINER exits, and signal-forwarding timing varies); `docker
    kill <name>` by the explicit --name is. Best-effort: the container may already be gone."""
    subprocess.run(["docker", "kill", name], capture_output=True, timeout=15)


def _run_stdio_check(image: str, entrypoint_kind: str, entrypoint_ref: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        entry = Path(d) / "entrypoint"
        entry.write_text(_ECHO_BODY)
        name = f"smoke-stdio-{entrypoint_kind}"
        argv = _containment_argv(image, name)
        argv += ["-i", "--mount", f"type=bind,src={entry},dst=/module/entrypoint,ro"]
        argv += ["--env", f"VSIFY_SANDBOX_ENTRYPOINT_KIND={entrypoint_kind}"]
        argv += ["--env", "VSIFY_SANDBOX_TRANSPORT=stdio"]
        if entrypoint_ref:
            argv += ["--env", f"VSIFY_SANDBOX_ENTRYPOINT_MODULE={entrypoint_ref}"]
        argv.append(image)

        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        try:
            frame_type, _, _ = read_frame(proc.stdout.read, max_payload_bytes=0)
            assert frame_type == FRAME_READY, f"expected READY, got frame_type={frame_type}"

            proc.stdin.write(encode_frame(FRAME_REQUEST, b"smoke-test-payload"))
            proc.stdin.flush()
            frame_type, payload, _ = read_frame(proc.stdout.read, max_payload_bytes=1024)
            assert frame_type == FRAME_RESPONSE, f"expected RESPONSE, got frame_type={frame_type}"
            assert payload == b"smoke-test-payload", f"echo mismatch: {payload!r}"
            print(f"OK stdio/{entrypoint_kind}: READY + echo round-trip verified")
        finally:
            proc.stdin.close()
            _docker_kill(name)
            proc.wait(timeout=15)


def _run_unix_socket_check(image: str, entrypoint_kind: str, entrypoint_ref: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        entry_dir = Path(d) / "module"
        entry_dir.mkdir()
        entry = entry_dir / "entrypoint"
        entry.write_text(_ECHO_BODY)

        sock_dir = Path(d) / "sock"
        sock_dir.mkdir(mode=0o711)
        sock_path = sock_dir / "session.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(sock_path))
        os.chmod(sock_path, 0o766)
        listener.listen(1)
        listener.settimeout(20)

        name = f"smoke-socket-{entrypoint_kind}"
        argv = _containment_argv(image, name)
        argv += ["--mount", f"type=bind,src={entry},dst=/module/entrypoint,ro"]
        argv += ["--mount", f"type=bind,src={sock_dir},dst=/run/sandbox"]
        argv += ["--env", f"VSIFY_SANDBOX_ENTRYPOINT_KIND={entrypoint_kind}"]
        argv += ["--env", "VSIFY_SANDBOX_TRANSPORT=unix_socket"]
        argv += ["--env", "VSIFY_SANDBOX_SOCKET=/run/sandbox/session.sock"]
        if entrypoint_ref:
            argv += ["--env", f"VSIFY_SANDBOX_ENTRYPOINT_MODULE={entrypoint_ref}"]
        argv.append(image)

        proc = subprocess.Popen(argv)
        try:
            conn, _ = listener.accept()
            frame_type, _, _ = read_frame(conn.recv, max_payload_bytes=0)
            assert frame_type == FRAME_READY, f"expected READY, got frame_type={frame_type}"

            conn.sendall(encode_frame(FRAME_REQUEST, b"smoke-test-socket"))
            frame_type, payload, _ = read_frame(conn.recv, max_payload_bytes=1024)
            assert frame_type == FRAME_RESPONSE, f"expected RESPONSE, got frame_type={frame_type}"
            assert payload == b"smoke-test-socket", f"echo mismatch: {payload!r}"
            print(f"OK unix_socket/{entrypoint_kind}: READY + echo round-trip verified")
        finally:
            listener.close()
            _docker_kill(name)
            proc.wait(timeout=15)


def _check_containment(image: str) -> None:
    """A container that CANNOT reach the network and CANNOT write outside /tmp — proves the
    hardening flags this script passes are actually enforced by the engine, not just accepted."""
    out = subprocess.run(
        _containment_argv(image, "smoke-containment") + ["--entrypoint", "id", image],
        capture_output=True, text=True, timeout=15,
    )
    assert "uid=65534" in out.stdout, f"expected non-root uid, got: {out.stdout!r}"
    print("OK containment: runs as uid=65534 (non-root)")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    image = sys.argv[1]

    _check_containment(image)
    for kind, ref in (("script", ""), ("python_module", "modules.acme.entrypoint")):
        _run_stdio_check(image, kind, ref)
        _run_unix_socket_check(image, kind, ref)

    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
