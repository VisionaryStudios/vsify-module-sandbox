"""``python -m vsify_sandbox`` — the image's ``ENTRYPOINT``. See ``entrypoint.py`` for the actual
dispatch logic; this file is deliberately a one-line delegator so `python -m` has a stable target
regardless of how the entrypoint module itself is organized."""
from .entrypoint import main

if __name__ == "__main__":
    raise SystemExit(main())
