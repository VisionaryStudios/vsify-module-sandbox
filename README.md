# vsify-module-sandbox — GENERATED MIRROR, DO NOT EDIT

This repository is **generated**. Its canonical source is `sandbox/` in
[`VisionaryStudios/vsify-enterprise-mcp`](https://github.com/VisionaryStudios/vsify-enterprise-mcp),
and it is republished from there on every framework release (ADR-P048 §1-§2).

- **Edit the source there, not here.** A change made in this repository is not merged back, and the
  next publish replaces this tree wholesale.
- **A hand-edit never becomes an image.** The build refuses any commit that lacks the publisher's
  `Framework-SHA:` trailer.
- **Refs.** Every framework release publishes an immutable tag named exactly as the framework tag and
  advances `rc`; `main` moves on GA releases only.
- **Images.** Each release tag builds `ghcr.io/visionarystudios/vsify-module-sandbox:<version>` (the
  tag without its leading `v`), verified by digest before the tag is pointed at it. `:latest` moves
  on GA releases only, and the framework never depends on it.
- **Pins.** `schemas/SANDBOX_WIRE.json` and `schemas/EGRESS_GRAMMAR.json` are rendered copies of the
  framework's own pins, which the tests here assert against.

See `PROVENANCE.md` for what moved where, and `CONTRIBUTING.md` for the release and rollback
procedures.
