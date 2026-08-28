"""``vsify_sandbox.entrypoint`` — module loading + the serve dispatch loop (ADR-P041). No real
Docker/socket/subprocess anywhere: the channel is a pure in-memory double, and the "module" is a
real temp file loaded via the actual ``importlib`` path.
"""
from __future__ import annotations

import io

import pytest

from vsify_sandbox import entrypoint
from vsify_sandbox.framing import (
    FRAME_ERROR,
    FRAME_READY,
    FRAME_REQUEST,
    FRAME_RESPONSE,
    encode_frame,
    read_frame,
)


class _FakeChannel:
    """Feeds pre-scripted incoming frames; records every outgoing write. ``read`` behaves like a
    real stream: returns queued bytes, then ``b""`` (EOF) once exhausted."""

    def __init__(self, incoming: bytes = b"") -> None:
        self._in = io.BytesIO(incoming)
        self.out = io.BytesIO()
        self.closed = False

    def read(self, n: int) -> bytes:
        return self._in.read(n)

    def write(self, data: bytes) -> None:
        self.out.write(data)

    def close(self) -> None:
        self.closed = True

    def written_frames(self):
        buf = io.BytesIO(self.out.getvalue())
        frames = []
        while True:
            try:
                frames.append(read_frame(buf.read, max_payload_bytes=entrypoint.MAX_RESPONSE_BYTES))
            except Exception:
                break
        return frames


@pytest.fixture
def echo_module(tmp_path, monkeypatch):
    """A minimal `serve(payload) -> payload` module, bind-mount-simulated at ENTRYPOINT_PATH.

    Named `entrypoint` with NO `.py` suffix — deliberately mirroring the real host bind-mount
    target exactly ("/module/entrypoint", never "entrypoint.py"). A `.py`-suffixed fixture here
    previously masked a real bug: `importlib.util.spec_from_file_location` infers its loader from
    the file suffix when none is given, silently returning `None` for an extension-less path — only
    caught by the real end-to-end Docker test (test_container_serving_e2e.py in the host repo),
    never by this file while the fixture used the wrong filename shape."""
    module_file = tmp_path / "entrypoint"
    module_file.write_text("def serve(payload: bytes) -> bytes:\n    return payload\n")
    monkeypatch.setattr(entrypoint, "ENTRYPOINT_PATH", str(module_file))
    return module_file


class TestLoadServeCallable:
    def test_script_kind_loads_the_module(self, echo_module, monkeypatch):
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "script")
        serve = entrypoint._load_serve_callable()
        assert serve(b"hi") == b"hi"

    def test_python_module_kind_with_a_valid_ref_loads(self, echo_module, monkeypatch):
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "python_module")
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_MODULE", "modules.acme.entrypoint")
        serve = entrypoint._load_serve_callable()
        assert serve(b"hi") == b"hi"

    def test_python_module_kind_with_a_malformed_ref_refuses(self, echo_module, monkeypatch):
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "python_module")
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_MODULE", "modules/../escape")
        with pytest.raises(entrypoint.SetupError):
            entrypoint._load_serve_callable()

    def test_unsupported_kind_refuses(self, echo_module, monkeypatch):
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "skill")
        with pytest.raises(entrypoint.SetupError):
            entrypoint._load_serve_callable()

    def test_missing_serve_callable_refuses(self, tmp_path, monkeypatch):
        module_file = tmp_path / "entrypoint"  # no .py suffix — mirrors the real mount target
        module_file.write_text("x = 1\n")  # no `serve` defined
        monkeypatch.setattr(entrypoint, "ENTRYPOINT_PATH", str(module_file))
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "script")
        with pytest.raises(entrypoint.SetupError) as ei:
            entrypoint._load_serve_callable()
        assert str(ei.value) == "serve_callable_missing"  # not entrypoint_unloadable

    def test_missing_entrypoint_file_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(entrypoint, "ENTRYPOINT_PATH", str(tmp_path / "does-not-exist.py"))
        monkeypatch.setenv("VSIFY_SANDBOX_ENTRYPOINT_KIND", "script")
        with pytest.raises(entrypoint.SetupError):
            entrypoint._load_serve_callable()


class TestServeForever:
    def test_sends_ready_first(self):
        channel = _FakeChannel(incoming=b"")  # EOF immediately after READY
        entrypoint._serve_forever(channel, serve=lambda payload: payload)
        frames = channel.written_frames()
        assert frames[0][0] == FRAME_READY

    def test_echoes_one_request_as_a_response(self):
        request = encode_frame(FRAME_REQUEST, b"ping")
        channel = _FakeChannel(incoming=request)
        entrypoint._serve_forever(channel, serve=lambda payload: payload)
        frames = channel.written_frames()
        assert frames[0][0] == FRAME_READY
        assert frames[1] == (FRAME_RESPONSE, b"ping", False)

    def test_a_raising_module_produces_an_error_frame_and_keeps_serving(self):
        req1 = encode_frame(FRAME_REQUEST, b"boom")
        req2 = encode_frame(FRAME_REQUEST, b"ok")

        def flaky_serve(payload: bytes) -> bytes:
            if payload == b"boom":
                raise ValueError("nope")
            return payload

        channel = _FakeChannel(incoming=req1 + req2)
        entrypoint._serve_forever(channel, serve=flaky_serve)
        frames = channel.written_frames()
        assert frames[0][0] == FRAME_READY
        assert frames[1][0] == FRAME_ERROR
        assert frames[2] == (FRAME_RESPONSE, b"ok", False)

    def test_oversize_response_is_truncated_with_the_flag_set(self, monkeypatch):
        monkeypatch.setattr(entrypoint, "MAX_RESPONSE_BYTES", 4)
        request = encode_frame(FRAME_REQUEST, b"x")
        channel = _FakeChannel(incoming=request)
        entrypoint._serve_forever(channel, serve=lambda payload: b"way too long")
        frames = channel.written_frames()
        assert frames[1][0] == FRAME_RESPONSE
        assert frames[1][1] == b"way "  # truncated to MAX_RESPONSE_BYTES
        assert frames[1][2] is True  # producer-set truncated flag

    def test_a_non_request_frame_is_ignored_not_replied_to(self):
        ready = encode_frame(FRAME_READY, b"")  # a stray, unexpected frame type
        request = encode_frame(FRAME_REQUEST, b"real")
        channel = _FakeChannel(incoming=ready + request)
        entrypoint._serve_forever(channel, serve=lambda payload: payload)
        frames = channel.written_frames()
        # our own READY, then the echoed response to the real request — never a reply to the stray frame
        assert frames == [(FRAME_READY, b"", False), (FRAME_RESPONSE, b"real", False)]


class TestConnectChannel:
    def test_unsupported_transport_refuses(self):
        with pytest.raises(entrypoint.SetupError):
            entrypoint._connect_channel("tcp_loopback")

    def test_unix_socket_without_a_path_env_refuses(self, monkeypatch):
        monkeypatch.delenv("VSIFY_SANDBOX_SOCKET", raising=False)
        with pytest.raises(entrypoint.SetupError):
            entrypoint._connect_channel("unix_socket")
