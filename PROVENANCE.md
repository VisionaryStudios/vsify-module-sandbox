# Provenance of `sandbox/`

**This tree is CANONICAL.** It is the one place the `vsify-module-sandbox` image source is edited
(ADR-P048 §1, `vsify-enterprise-mcp:docs/architecture/decisions/platform/ADR-P048-sandbox-co-versioning.md`).
The `VisionaryStudios/vsify-module-sandbox` repository becomes a generated, **DO-NOT-EDIT** mirror
of it, published on every framework release through the ADR-G011 mirror model (ADR-P048 §2). A
hand-edit to the mirror is not merged back: the next publish replaces the mirror tree wholesale.

## Migrated from

| field | value |
|---|---|
| source repository | `VisionaryStudios/vsify-module-sandbox` |
| source commit | `dfbadc7` (`dfbadc781e0ca17121196034e6246210cb7bd178`) |
| migrated on | 2026-09-27 |
| decision record | ADR-P048 §1 (source ownership), §8 (in-tree CI build), §9 (dependency tracking) |

Every file below was copied byte-identical from that commit unless it is listed under **Changed on
migration**.

- `vsify_sandbox/` — `__init__.py`, `__main__.py`, `entrypoint.py`, `entrypoint_resolve.py`,
  `framing.py`
- `Dockerfile`, `.trivyignore`, `pyproject.toml`
- `scripts/smoke_test.py`
- `tests/` — `test_contributing_references_resolve.py`, `test_dockerfile_base_pin.py`,
  `test_entrypoint_dispatch.py`, `test_entrypoint_resolve.py`, `test_trivyignore_policy.py`,
  `test_wire_conformance.py`
- `CONTRIBUTING.md`
- `.github/workflows/build-verify-promote.yml`, `.github/workflows/rollback-latest.yml`
- `.github/actions/trivy-scan/action.yml` — not named in the story's file list, but both workflows
  above call it as `./.github/actions/trivy-scan`, so the mirror cannot build without it. The host's
  `sandbox-base-image-watch.yml` references the same file in place rather than keeping a copy.

## Changed on migration

- `tests/test_wire_conformance.py` — reads the host pin `../schemas/SANDBOX_WIRE.json` when run
  in-tree, the mirror's rendered `schemas/SANDBOX_WIRE.json` otherwise, and fails by name when the
  pin is absent.
- `tests/test_contributing_references_resolve.py` — in-tree, `vsify-enterprise-mcp:` referents are
  also asserted to exist, because the host is now the directory this tree sits in.
- `CONTRIBUTING.md` — a *Where this source lives* section; references to files that now live only in
  the host carry the `vsify-enterprise-mcp:` prefix; step `W5` (copy the wire pin between
  repositories) is marked superseded in place, keeping its id.

## Not migrated, and where each went

| image-repo path | now |
|---|---|
| `schemas/SANDBOX_WIRE.json` | **Dropped.** The host's `schemas/SANDBOX_WIRE.json` is the single source (it was byte-identical at migration, sha256 `40d5b802…9316`). The mirror receives a copy rendered from it (ADR-P048 §2). `vsify-enterprise-mcp:tests/test_sandbox_tree_provenance.py` refuses a copy under `sandbox/`. |
| `.github/dependabot.yml` | Its docker entry moved to the host's `.github/dependabot.yml`, directory `/sandbox` (ADR-P048 §9). |
| `.github/workflows/base-image-watch.yml` | Ported to the host as `.github/workflows/sandbox-base-image-watch.yml`, watching `sandbox/Dockerfile` (ADR-P048 §9). |
| `README.md`, `.gitignore`, `.github/PULL_REQUEST_TEMPLATE.md` | Mirror-repo presentation, owned by the mirror render (with its DO-NOT-EDIT banner), not by this source tree. |
