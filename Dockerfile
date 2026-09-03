# vsify-module-sandbox — ADR-P041 sandbox execution image.
#
# Minimal surface by design (ADR-P017's "least new infrastructure" philosophy): stdlib-only, no
# pip installs, non-root, no shell in the final image. The host (vsify-enterprise-mcp's
# ContainerIsolationBackend) supplies every runtime flag (--network, --read-only, --cap-drop,
# resource caps) — this image does not and cannot loosen any of them; it just has to behave
# correctly INSIDE whatever containment the host already constructed.
#
# THE BASE IS DIGEST-PINNED AND WRITTEN INLINE — no `ARG BASE_IMAGE` indirection (issue #352).
# Three measured reasons, in the order they matter:
#
#   1. Dependabot CANNOT resolve `ARG BASE_IMAGE=...` + `FROM ${BASE_IMAGE}`. This is not a
#      version-dependent quirk to wait out: dependabot-core #4597 and #10190 are both closed as
#      NOT PLANNED. The indirection made this image's base permanently invisible to the docker
#      ecosystem — a `.github/dependabot.yml` pointed at the old Dockerfile would have parsed
#      cleanly, run weekly, found zero dependencies, and opened zero PRs. Coverage in appearance
#      only, which is worse than none.
#   2. Dependabot compares tag STRINGS. `python:3.12-slim` is republished IN PLACE when upstream
#      ships a patched openssl/libc, so a floating tag never yields a PR for exactly the event
#      issue #352 exists to catch. Only a digest moves. The TAG MUST STAY on this line alongside
#      the digest — tag+digest is tracked and updated together; a bare digest is untracked.
#   3. A digest also defeats a tag repoint (an upstream tag hijacked or overwritten by mistake).
#
# Nothing ever passed `--build-arg BASE_IMAGE` and nothing in `vsify_sandbox/` reads it, so this
# removes an unused override surface rather than a capability. ADR-P041 § Explicitly Out of Scope
# rules out a base-image build-arg MATRIX; removing the ARG moves further from a matrix, not
# closer — but that bullet also called the ARG line "the honest phase-1 shape", so it is amended
# to v1.4 in vsify-enterprise-mcp alongside this change. See CONTRIBUTING.md step `B1`.
#
# This is the MULTI-ARCH OCI INDEX digest for python:3.12-slim (8 platforms, incl. linux/amd64 and
# linux/arm64v8) — NOT a platform-specific manifest digest, which would build on CI (amd64) and
# break on an arm64 dev machine. CONTRIBUTING.md step `B2` is how that stays true.
#
# `AS runtime` names the only stage this image has, and is the seam for a future dependency layer:
# a `FROM ... AS builder` stage plus one `COPY --from=builder` lands above it without touching the
# WORKDIR/COPY/USER/ENTRYPOINT lines below, and with no change to build → verify → promote (which
# is keyed on the pushed digest, never on this file's internal shape). See step `B5`.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS runtime

WORKDIR /app
COPY --chown=65534:65534 vsify_sandbox/ /app/vsify_sandbox/

# Matches the host's default run_user ("65534:65534" — container_backend.py). Switched to LAST,
# after WORKDIR/COPY (which need root to create /app) — a non-root UID cannot create a directory
# under a root-owned "/". A UID with no passwd entry inside the image is intentional (least
# privilege; nothing here needs a home dir or shell).
USER 65534:65534

ENTRYPOINT ["python", "-m", "vsify_sandbox"]
