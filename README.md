# vsify-module-sandbox

The sandbox execution image for [`vsify-enterprise-mcp`](https://github.com/VisionaryStudios/vsify-enterprise-mcp)'s `signed-quarantined` capability modules. Built and consumed against the wire contract and design decisions recorded in [ADR-P041](https://github.com/VisionaryStudios/vsify-enterprise-mcp/blob/main/docs/architecture/decisions/platform/ADR-P041-sandbox-serving-wire-contract.md) — read that ADR first; this README is a pointer, not a duplicate.

## What this is

`ContainerIsolationBackend` (in vsify-enterprise-mcp) launches this image inside a hardened, host-controlled `docker run` — `--network none`, `--read-only` rootfs, `--cap-drop ALL`, non-root user, resource caps, all constructed by the host, none of it configurable from inside this image. This image's job is narrow: honor `SandboxSpec.entrypoint_kind` (`script` | `python_module`) for whichever module the host bind-mounts at `/module/entrypoint`, and speak the ADR-P041 wire contract over whichever transport (`stdio` | `unix_socket`) the host selects.

## Wire contract

12-byte header + payload: `MAGIC(4=b"VSB1")` + `VERSION(u16 BE)` + `TYPE(u8)` + `FLAGS(u8, bit0=truncated)` + `LENGTH(u32 BE)` + `payload`. Frame types: `READY=0`, `REQUEST=1`, `RESPONSE=2`, `ERROR=3`. `schemas/SANDBOX_WIRE.json` is the golden-vector conformance pin, vendored byte-identical from the host repo — `tests/test_wire_conformance.py` here asserts this image's codec against the same vectors the host repo's own test asserts its codec against, so the two can never silently drift.

## Dispatch environment variables

All non-secret, all set by the host's `ContainerIsolationBackend._build_serving_argv`:

| Variable | Values | Notes |
|---|---|---|
| `VSIFY_SANDBOX_TRANSPORT` | `stdio` \| `unix_socket` | which channel to serve over |
| `VSIFY_SANDBOX_ENTRYPOINT_KIND` | `script` \| `python_module` | always set |
| `VSIFY_SANDBOX_ENTRYPOINT_MODULE` | a dotted ref, e.g. `modules.acme.entrypoint` | only for `python_module` — re-validated here, never trusted blindly |
| `VSIFY_SANDBOX_SOCKET` | an in-container path | only for `unix_socket` |

The module itself is always bind-mounted read-only at `/module/entrypoint` by the host — this image never resolves a dotted ref to a file path itself (there is no repo tree inside the container); it loads that one file directly and binds its required `serve(payload: bytes) -> bytes` callable.

## Platform note

`unix_socket` requires **native Linux Docker** to work end-to-end — Docker Desktop for Mac/Windows runs containers in a Linux VM, and a live `AF_UNIX` socket cannot cross that VM boundary via a bind mount (the container sees a correctly-typed socket file but `connect()` returns `ECONNREFUSED`). This is expected there, not a defect — GitHub Actions runners and real production Docker deployments use native Linux Docker. `stdio` has no such dependency.

## CI

`.github/workflows/build-verify-promote.yml`: **build** (buildx, pushes to `ghcr.io/visionarystudios/vsify-module-sandbox:sha-<gitsha>` only, never `:latest`) → **verify** (pulls by digest, runs the conformance suite against both transports × both entrypoint kinds, asserts non-root/read-only/network-none, then Trivy-scans that same digest and fails on any CRITICAL/HIGH **with a fix available**) → **promote** (only on a green verify: moves `:latest` to the already-verified digest via `docker buildx imagetools create` — never a rebuild-to-promote, so a failed pipeline can never move the tag). Publishes using this repo's own automatic `GITHUB_TOKEN` (`permissions: packages: write`) — no shared App token.

The base image is **digest-pinned** (`python:3.12-slim@sha256:…`, the multi-arch index digest) and
watched by `.github/dependabot.yml` across the `docker` and `github-actions` ecosystems. The pin is
not a style choice: Dependabot compares tag strings, so a floating tag never surfaces an upstream
security republish of the same tag — and it cannot resolve an `ARG`-indirected `FROM` at all.

`.github/workflows/base-image-watch.yml` runs weekly and reds if the pin has drifted from upstream
with no Dependabot PR behind it (the ecosystem is broken, not merely idle), or if the image
`:latest` currently points at has acquired a fixable CRITICAL/HIGH since it was built.
`.github/workflows/rollback-latest.yml` re-verifies a prior digest and repoints `:latest` without a
rebuild.

## Development

```bash
pip install pytest ruff  # or use any Python 3.12 environment
pytest tests/
ruff check .
docker build -t vsify-module-sandbox:local .
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing the wire format or the base image. It holds
the two cross-repo checklists — `W1`–`W9` for a `schemas/SANDBOX_WIRE.json` change (which must land
byte-identically in both repositories, and which nothing copies automatically) and `B1`–`B6` for the
base-image pin, the vulnerability gate, and its bounded escape hatch.
