# Contributing to vsify-module-sandbox

This repository ships exactly one artifact: the ADR-P041 sandbox execution image that runs
**signed-quarantined** (third-party, human-approved-but-not-trusted) capability modules for
[`vsify-enterprise-mcp`](https://github.com/VisionaryStudios/vsify-enterprise-mcp).

Design authority is **ADR-P041**
(`vsify-enterprise-mcp:docs/architecture/decisions/platform/ADR-P041-sandbox-serving-wire-contract.md`).
It is normative for the wire format, the base image, and the CI pipeline shape. Where this
document and that ADR disagree, **the ADR wins and this document is the bug.**

Most of what goes wrong in a repo this small is not a code defect. It is a **cross-repo desync** or
a **supply-chain drift** — neither of which any test here can see on its own. That is what the two
checklists below are for.

---

## Notation

Two conventions, both cheap and both deliberate, so that a later decision to mechanise any of this
**reads this document rather than replacing it**.

- **Every checklist step has a stable id** in backticks — `W3`, `B5`. Ids are append-only: never
  renumber a step, add a new one. Comments in `Dockerfile` and
  `.github/workflows/build-verify-promote.yml` already cite these ids by name.
- **A referent in the other repository is prefixed** `vsify-enterprise-mcp:` — e.g.
  `vsify-enterprise-mcp:tests/test_sandbox_wire_conformance.py`. A referent in *this* repository is
  a plain repo-relative path — e.g. `tests/test_wire_conformance.py`. That one prefix is what lets
  `tests/test_contributing_references_resolve.py` distinguish "lives in the other repo" from
  "does not exist anywhere", and it is the syntax a future cross-repo parity check would consume.

`tests/test_contributing_references_resolve.py` asserts that every local path named here exists and
that step ids stay unique. **It cannot assert the steps are correct, complete, or well-ordered** —
that is a human obligation, which is exactly why issue #353 asked for a checklist and not
automation.

---

## The two coupling surfaces

|                | Wire contract                | Base image                      |
| -------------- | ---------------------------- | ------------------------------- |
| Initiated by   | a human, deliberately        | Dependabot, on a schedule       |
| Direction      | symmetric — both repos move  | one-way, upstream → here        |
| Cadence        | rare, semantic               | continuous, mechanical          |
| Procedure      | `W1`–`W9` below              | `B1`–`B6` below                 |

They are kept apart on purpose. Routing base bumps through the wire checklist would fire it most
weeks for no wire reason, and a checklist that cries wolf stops being read — which destroys the
only thing it buys. Both surfaces converge on one observable outlet: a new digest promoted to
`:latest` by `.github/workflows/build-verify-promote.yml`. That pipeline is the coordinator. There
is no second one, and none should be built.

---

## Wire-contract sync checklist (issue #353)

`schemas/SANDBOX_WIRE.json` exists **byte-identically** in two repositories:

| Repo                          | Codec                        | Test that asserts the codec against the vectors        |
| ----------------------------- | ---------------------------- | ------------------------------------------------------ |
| `vsify-enterprise-mcp` (host) | `vsify-enterprise-mcp:vsify_enterprise_mcp/isolation/wire_framing.py` | `vsify-enterprise-mcp:tests/test_sandbox_wire_conformance.py` |
| `vsify-module-sandbox` (image) | `vsify_sandbox/framing.py`  | `tests/test_wire_conformance.py`                       |

Nothing copies the file. Each side's conformance test only catches drift *after* both sides have
already been edited independently, and nothing in either repo's CI fails a PR because the *other*
repo's copy fell behind. This checklist does not close that gap mechanically. It makes it much
harder to forget a step mid-change.

> **Do not trust `schemas/SANDBOX_WIRE.json`'s own `$schema_note` on this point.** It names the host-side
> asserter as `vsify-enterprise-mcp:tests/test_wire_framing.py`. That file exists in the host repo — so this is a
> misattribution, not a dangling path, and it will not look wrong at a glance — but it is a pure
> codec unit test that never opens `schemas/SANDBOX_WIRE.json`. Running it proves nothing about vector
> drift. The table above is correct; the `$schema_note` is not. Correcting the note edits the
> byte-identical file, so it is itself a full `W1`–`W9` change and is deliberately left for a PR
> that can exercise this checklist rather than fixed in passing.

- [ ] **`W1` — Classify the change first, in writing.** Is it **(a) additive** — a new golden
      vector, a new description, no existing frame's bytes move — or **(b) a `WIRE_VERSION` bump
      or a change to any existing vector's `frame_hex`**? The two have entirely different
      procedures. State which in the PR description before doing anything else.

- [ ] **`W2` — If (b): STOP. This is a flag day, not a checklist item.** Three facts compose into
      an outage:
      1. `vsify-enterprise-mcp:vsify_enterprise_mcp/isolation/wire_framing.py` raises
         `version_mismatch` on any version that is not its own. A hard refusal.
      2. ADR-P041 rules a framing-version **handshake** explicitly out of scope, so there is no
         negotiation to fall back on.
      3. The host's `ContainerIsolationBackend.default_image` is
         `ghcr.io/visionarystudios/vsify-module-sandbox:latest` — an **unpinned, mutable tag**.
         (A `SandboxSpec` *may* carry its own `image` and pin itself; the shipped default does
         not.)

      So promoting a new image instantly breaks every host on the default path, and landing the
      new host first breaks it against the still-promoted old image. **There is no merge order
      that works.** Resolve ADR-P041's digest-pin Named Residual (a host-side digest pin, so the
      host can hold back), **or** ship dual-version decode on the host, **before** `W3` onward.
      This is the step this checklist most exists for.

- [ ] **`W3` — Change the codec in exactly ONE repo first** — `vsify_sandbox/framing.py` here, or
      `vsify-enterprise-mcp:vsify_enterprise_mcp/isolation/wire_framing.py` there — and treat that
      side as the source for this change. Never edit both and reconcile; that is how byte-identity
      is lost.

- [ ] **`W4` — Regenerate the golden vectors from the updated codec.** There is **no generator
      script** in either repo; `schemas/SANDBOX_WIRE.json` is hand-maintained. Recompute rather
      than hand-editing `frame_hex`:

      ```bash
      python - <<'PY'
      import json, pathlib
      from vsify_sandbox.framing import encode_frame
      p = pathlib.Path("schemas/SANDBOX_WIRE.json")
      doc = json.loads(p.read_text())
      for v in doc["vectors"]:
          v["frame_hex"] = encode_frame(
              v["frame_type"], bytes.fromhex(v["payload_hex"]), truncated=v["truncated"]
          ).hex()
      p.write_text(json.dumps(doc, indent=2) + "\n")   # ensure_ascii default: the file uses \uXXXX
      PY
      ```

      Then read the diff. If no vector's bytes moved, the change was internal-only — which is the
      question `W7` turns on.

- [ ] **`W5` — Copy the file byte-identical into the other repo, and prove it.** A
      re-serialisation (reordered keys, a changed trailing newline, a literal em dash where the
      file had `—`) is a silent break that both conformance suites will still pass.

      ```bash
      cp schemas/SANDBOX_WIRE.json ../vsify-enterprise-mcp/schemas/SANDBOX_WIRE.json
      shasum -a 256 schemas/SANDBOX_WIRE.json ../vsify-enterprise-mcp/schemas/SANDBOX_WIRE.json
      ```

      Two identical hashes, pasted into both PR descriptions, or you are not done.

- [ ] **`W6` — Mirror the codec change into the other repo's codec.** `MAGIC` and `WIRE_VERSION`
      are asserted against the JSON on both sides; they move together or not at all.

- [ ] **`W7` — Bump `WIRE_VERSION` only if the ON-WIRE FORMAT changed**, not for an internal
      implementation change. The bump must agree in three places: both codecs and the
      `wire_version` key in `schemas/SANDBOX_WIRE.json`. If you are bumping, `W2` applies and you
      should already have resolved it.

- [ ] **`W8` — Update ADR-P041's frame-format section** in the host repo, and bump its front-matter
      `version:` and `date_modified:`. The ADR is the contract's definition; these two codebases
      are its implementations.

- [ ] **`W9` — Re-run BOTH conformance suites, then open both PRs cross-linked.**
      `pytest tests/test_wire_conformance.py` here, and
      `pytest vsify-enterprise-mcp:tests/test_sandbox_wire_conformance.py` there. Green on one
      side proves nothing about the other. Neither PR merges alone; on the additive path (a)
      either merge order is safe *only* because adding a vector changes no encoder output — do not
      generalise that to any other change.

### Not a wire-contract change

Entrypoint resolution, transport plumbing, `Dockerfile`, CI config. Image-repo-only, no host PR.

---

## Base image and the digest pin (issue #352)

`Dockerfile` pins `python:3.12-slim@sha256:<digest>` — **tag and digest both**.

- The **tag** is how Dependabot knows which family to resolve. Delete it and updates stop silently.
- The **digest** is what makes an in-place republish of `python:3.12-slim` visible at all.
  Dependabot compares tag strings, so a floating tag never yields a PR when upstream patches
  openssl — which is the entire event issue #352 was filed about.
- **Never reintroduce `ARG BASE_IMAGE` / `FROM ${BASE_IMAGE}`.** Dependabot cannot resolve it
  (dependabot-core #4597 and #10190, both closed NOT PLANNED). The indirection is a silent no-op
  that reads as coverage.

- [ ] **`B1` — The base TAG is normative in ADR-P041.** Changing `3.12-slim` to anything else is an
      ADR amendment with a two-repo review, never a Dependabot merge. Changing the *digest* of that
      tag is routine. `.github/dependabot.yml` refuses to propose the former.

- [ ] **`B2` — Confirm the new digest is the MULTI-ARCH OCI INDEX digest**, not a platform-specific
      manifest digest. A per-platform digest builds fine on CI (amd64) and breaks `docker build` on
      an arm64 dev machine.

      ```bash
      docker buildx imagetools inspect python:3.12-slim --format '{{ .Manifest.Digest }}'
      ```

- [ ] **`B3` — Merge only on a green `verify`.** That job rebuilds, smoke-tests both transports ×
      both entrypoint kinds against the new digest, and scans it — so a base rebase that breaks the
      entrypoint or introduces a *fixable* CRITICAL/HIGH is caught before `promote` can move
      `:latest`.

- [ ] **`B4` — One-time, on the first Dependabot run:** confirm the `ignore` rules in
      `.github/dependabot.yml` suppress a 3.13 proposal but do **not** suppress digest-only updates
      of the pinned `3.12-slim` tag. (`version-update:semver-*` governs version changes, and a
      digest-only update carries none — but verify rather than assume.) Also confirm the `build`
      job's `packages: write` actually takes effect under Dependabot's restricted token; if it does
      not, the PR reds for a permissions reason and the fix is a workflow change, not a re-run.

- [ ] **`B5` — If this image ever gains a runtime dependency** (today it has none — no
      `pip install`, an ADR-P041 MUST NOT), do all three: re-evaluate `ignore-unfixed: true` in the
      Trivy gate, because with real dependencies unfixed findings become actionable and the flag
      stops being honest; add the install in a `FROM ... AS builder` stage and `COPY --from=builder`
      into `runtime`, so the final layer keeps no build tooling; and add a lockfile plus a matching
      `pip` ecosystem entry to `.github/dependabot.yml`.

- [ ] **`B6` — If Trivy reddens on something you cannot fix now**, the escape hatch is a
      `.trivyignore` entry with a CVE id, a `# why:` line naming a tracking issue, and an
      `exp:YYYY-MM-DD` date at most 30 days out — never a broadened `severity`, never a removed
      `exit-code`, and never `continue-on-error`. `tests/test_trivyignore_policy.py` enforces the
      form, Trivy itself stops honouring the line on its date, and every live suppression is
      printed into the `verify` job summary on every run.

### Reviewing a Dependabot base-image PR

1. The diff is one line and the tag is unchanged (`python:3.12-slim`).
2. `verify` is green — smoke test **and** the Trivy gate ran against the new digest.
3. Merge. `promote` then moves `:latest` from that already-verified digest.

---

## The vulnerability gate

`.github/workflows/build-verify-promote.yml` runs Trivy twice in `verify`, against the built
**digest**, before `promote`:

| Pass  | Purpose                                                            | Gates? |
| ----- | ------------------------------------------------------------------ | ------ |
| SARIF | the full CRITICAL/HIGH picture **including unfixed**, to code scanning | no  |
| table | CRITICAL/HIGH **with a fix available**                             | **yes** |

Gating on fixed-only is deliberate. The base carries ~18 unfixed CRITICAL/HIGH at any time;
blocking on those would mean nothing ever promotes, and the first person to hit it would delete the
gate. Gating on *fixable* means the gate reddens exactly when a remedy exists and has not been
taken. The unfixed set is not hidden — it goes to the Security tab on every run.

The gate is **fail-closed**: Trivy exits non-zero on a fatal error, including a trivy-db fetch
failure or a GHCR rate limit, so scanner trouble blocks the promote rather than skipping the scan.
**Never add `continue-on-error` to a scan step.** That single change converts this gate into
decoration.

`.github/workflows/base-image-watch.yml` runs weekly and closes the two things the build pipeline
structurally cannot see: whether the pin has drifted with no Dependabot PR behind it (the ecosystem
is broken), and whether the image production is running *right now* has acquired a fixable CVE
since it was built.

---

## Rollback

Nothing here needs a rebuild. Every build is published as `:sha-<gitsha>`, and `:latest` is only
ever a pointer.

**A Dependabot digest bump that breaks the smoke test cannot reach production** — `verify` reds on
the PR, the PR does not merge, `promote` never runs.

**A promoted image that misbehaves** (green verify, behavioural regression — the case ADR-P041's
Named Residual leaves open, since the host consumes `:latest`):

1. Find the last-good digest:
   ```bash
   gh api "/orgs/VisionaryStudios/packages/container/vsify-module-sandbox/versions" \
     --jq '.[] | {digest: .name, tags: .metadata.container.tags, created: .created_at}' | head -40
   ```
2. **Actions → rollback-latest → Run workflow** with that digest and a reason
   (`.github/workflows/rollback-latest.yml`). It re-runs the full smoke test against the digest
   *before* moving the tag, so ADR-P041's "only from an already-verified digest" holds on the
   emergency path too.
3. Because the host consumes the tag, `:latest` moving back **is** the production rollback — no
   coordinated two-repo release.
4. Open an issue against the bad digest. A rollback with no follow-up becomes a permanent pin
   nobody remembers making.

---

## Development

```bash
pip install pytest ruff   # or any Python 3.12 environment
pytest tests/
ruff check .
docker build -t vsify-module-sandbox:local .
```

`pyproject.toml` declares no runtime dependencies and `Dockerfile` runs no `pip install`. Both are
ADR-P041 constraints, not accidents.

## PR and commit hygiene

- **GitHub Flow:** short-lived `<type>/<slug>` branches → PR → `main`. There is no `develop`.
- **Conventional Commits**, ADR-G001's eight types: `feat:` `fix:` `perf:` `refactor:` `docs:`
  `test:` `ci:` `chore:`. Subject ≤ 72 characters.
- **Do NOT put GitHub issue refs in commit messages** — no `Closes`/`Fixes`/`Refs #N`, and no bare
  `#N` footer. Put `Closes #N` (one per line) in the **PR description** only. Release tooling
  echoes commit-footer refs into the rolling release PR and churns issue and board state.
