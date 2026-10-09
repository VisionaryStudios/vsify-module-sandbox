# Loader corpus — the shared cases for the entrypoint analyser and loader

One corpus, run against every copy of the code it describes:

- the image's own copy, `vsify_sandbox/import_closure.py` + `vsify_sandbox/module_loader.py`
  (`tests/test_import_closure.py`, `tests/test_module_loader_corpus.py`);
- the host package's byte-identical mirror, `vsify_enterprise_mcp/_sandbox_mirror/`
  (the framework's `tests/test_sandbox_loader_parity.py`).

`sandbox/` is the source of truth (ADR-P048). Add a case here, never in a copy of it.

## Why the sources are `*.src`, not `*.py`

Several cases are deliberately broken (a syntax error, a bad encoding cookie). With a `.py` suffix the
sandbox's ruff run, and any tool that walks Python files, would trip over them. Nothing ever imports
these files: the tests read their bytes and hand them to the analyser or write them to a temporary
entrypoint path.

## `CASES.json`

Three tables:

| Table | Each row | Asserted against |
|---|---|---|
| `classify` | `id`, `source`, `expect` (a reason token or `null`) | `_classify_imports(source_bytes)` |
| `load` | `id`, `source`, `kind`, `module_ref`, `expect` (`"ok"` or a reason token), optional `setup`, `swap_source`, `serve_io` | `_load_entrypoint(...)`, and `serve(bytes.fromhex(in_hex)) == bytes.fromhex(out_hex)` when `ok` |
| `dotted_refs` | `ref`, `expect` (the segment list, or `"entrypoint_ref_malformed"`) | `_validate_dotted_ref(ref)`, and the host's `entrypoint_ref._dotted_ref_candidates` |

### `source`

- `{"file": "<name>.src"}` — the file's bytes, unchanged.
- `{"segments": [[text, times], ...], "encoding": "utf-8"}` — a SYNTHESISED source:
  `"".join(text * times for text, times in segments).encode(encoding)` (`encoding` defaults to
  `utf-8`). This carries the cases a checked-in file cannot hold cleanly: over the 1 MiB cap, nesting
  beyond the parser's limit, a NUL byte, and non-UTF-8 bytes under a `latin-1` cookie.
- `null` — no file at all (only with `setup: "missing"` or `"directory"`).

### `setup` (load table only)

| Value | Meaning |
|---|---|
| absent | write the source to the entrypoint path |
| `missing` | the entrypoint path does not exist |
| `directory` | the entrypoint path is a directory |
| `symlink` | write the source elsewhere and make the entrypoint path a symlink to it |
| `swap_after_classify` | the test's classifier overwrites the entrypoint with `swap_source` the moment it is called, then delegates to the real analyser. The loader must run the bytes it classified, not the swapped file |

## Reason tokens

The analyser's three are internal (ADR-P039): host-side each collapses to the single fixed
`entrypoint_unresolvable` launch outcome, so ADR-P036's closed vocabulary is unchanged.

| Token | From |
|---|---|
| `entrypoint_relative_import` | analyser — any `from . import x` / `from ..p import x`, anywhere in the tree |
| `entrypoint_nonstdlib_import` | analyser — an absolute import whose top-level name is not in the frozen `_STDLIB` |
| `entrypoint_unparseable` | analyser — over 1 MiB, not parseable, or any analyser fault (it never raises) |
| `entrypoint_symlink_refused` | loader — the entrypoint path is a symlink |
| `entrypoint_missing`, `entrypoint_unloadable`, `entrypoint_ref_malformed`, `unsupported_entrypoint_kind:<kind>`, `entrypoint_import_failed:<ExcType>`, `serve_callable_missing` | loader — unchanged from the image's previous loader |
