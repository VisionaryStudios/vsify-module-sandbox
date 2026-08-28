# vsify-module-sandbox — ADR-P041 sandbox execution image.
#
# Minimal surface by design (ADR-P017's "least new infrastructure" philosophy): stdlib-only, no
# pip installs, non-root, no shell in the final image. The host (vsify-enterprise-mcp's
# ContainerIsolationBackend) supplies every runtime flag (--network, --read-only, --cap-drop,
# resource caps) — this image does not and cannot loosen any of them; it just has to behave
# correctly INSIDE whatever containment the host already constructed.
ARG BASE_IMAGE=python:3.12-slim

FROM ${BASE_IMAGE}

WORKDIR /app
COPY --chown=65534:65534 vsify_sandbox/ /app/vsify_sandbox/

# Matches the host's default run_user ("65534:65534" — container_backend.py). Switched to LAST,
# after WORKDIR/COPY (which need root to create /app) — a non-root UID cannot create a directory
# under a root-owned "/". A UID with no passwd entry inside the image is intentional (least
# privilege; nothing here needs a home dir or shell).
USER 65534:65534

ENTRYPOINT ["python", "-m", "vsify_sandbox"]
