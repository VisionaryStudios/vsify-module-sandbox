"""``python -m vsify_sandbox`` — the image's ``ENTRYPOINT``. See ``entrypoint.py`` for the module
dispatch logic; this file only chooses WHICH program the image runs, so ``python -m`` has a stable
target regardless of how those modules are organized.

* ``--probe``: the gateway's per-container health check (ADR-P058 §5) — one TCP connect to the
  address the gateway wrote, exit 0 or 1.
* ``VSIFY_SANDBOX_MODE=egress-gateway``: the session egress gateway (ADR-P058). Branched on BEFORE
  ``entrypoint`` is imported, so the gateway never loads the module-serving code.
* any other non-empty mode: refused, exit 2 — an unknown mode never falls through to serving a module.
* empty or absent: the module entrypoint, exactly as before.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence

MODE_ENV = "VSIFY_SANDBOX_MODE"
GATEWAY_MODE = "egress-gateway"
PROBE_FLAG = "--probe"


def dispatch(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if environ is None else environ
    if args == [PROBE_FLAG]:
        from .egress_gateway import probe

        return probe()
    mode = env.get(MODE_ENV, "")
    if mode == GATEWAY_MODE:
        from .egress_gateway import main as gateway_main

        return gateway_main()
    if mode:
        sys.stderr.write(f"vsify-module-sandbox: unknown {MODE_ENV}; refusing to start\n")
        return 2
    from .entrypoint import main

    return main()


if __name__ == "__main__":
    raise SystemExit(dispatch())
