"""`scripts/verify_matrix.py` turns a pushed image index into the verify matrix (issue #672).

`verify` used to pull, smoke-test and scan ONE member of whatever index `build` pushed -- the
runner's own platform -- and `promote` then moved the tag to the whole index. That was harmless
while the index held one platform. With `linux/arm64` published beside `linux/amd64`, it would
promote a member nothing had verified. The matrix is therefore derived FROM THE DIGEST: every
platform the index carries gets a leg, so an unverified member cannot reach a tag by construction.

These tests pin the fail-closed edges: an attestation entry is not a platform, a platform with no
native runner refuses rather than being skipped, and a caller that names the set it built refuses
an index that carries anything else.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import load_script_module

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_matrix.py"
vm = load_script_module("verify_matrix", "scripts/verify_matrix.py")

_OCI_INDEX = "application/vnd.oci.image.index.v1+json"


def _member(arch: str, os_: str = "linux", variant: str | None = None) -> dict:
    platform = {"architecture": arch, "os": os_}
    if variant:
        platform["variant"] = variant
    return {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "a" * 64,
            "platform": platform}


def _attestation() -> dict:
    # What buildx writes for `provenance: true` / `sbom: true`: one entry per platform, unknown/unknown.
    entry = _member("unknown", "unknown")
    entry["annotations"] = {"vnd.docker.reference.type": "attestation-manifest"}
    return entry


def _index(*members: dict) -> dict:
    return {"schemaVersion": 2, "mediaType": _OCI_INDEX, "manifests": list(members)}


def test_every_platform_in_the_index_gets_a_native_leg():
    rows = vm.matrix(_index(_member("amd64"), _attestation(), _member("arm64"), _attestation()))
    assert rows == [
        {"platform": "linux/amd64", "arch": "amd64", "runner": "ubuntu-latest"},
        {"platform": "linux/arm64", "arch": "arm64", "runner": "ubuntu-24.04-arm"},
    ]


def test_a_pre_672_single_platform_index_still_verifies():
    # Every digest published before #672 is amd64 + attestation. rollback-latest must still be able
    # to re-verify one, so the matrix follows the target rather than assuming today's build set.
    assert vm.matrix(_index(_member("amd64"), _attestation())) == [
        {"platform": "linux/amd64", "arch": "amd64", "runner": "ubuntu-latest"},
    ]


def test_the_arm64_v8_variant_is_the_same_platform():
    rows = vm.matrix(_index(_member("arm64", variant="v8")))
    assert rows == [{"platform": "linux/arm64", "arch": "arm64", "runner": "ubuntu-24.04-arm"}]


def test_a_platform_without_a_native_runner_refuses_rather_than_skipping():
    with pytest.raises(vm.MatrixError, match="linux/arm/v7"):
        vm.matrix(_index(_member("amd64"), _member("arm", variant="v7")))


def test_an_index_with_only_attestations_refuses():
    with pytest.raises(vm.MatrixError, match="no platform"):
        vm.matrix(_index(_attestation()))


def test_a_single_manifest_refuses_instead_of_guessing_its_platform():
    # This pipeline always pushes an index (provenance/sbom attach as index entries). A bare
    # manifest carries no platform here, and guessing one would verify a member by assumption.
    with pytest.raises(vm.MatrixError, match="not an image index"):
        vm.matrix({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"})


def test_require_accepts_exactly_the_built_set_in_any_order():
    index = _index(_member("arm64"), _member("amd64"))
    assert [r["platform"] for r in vm.matrix(index, require="linux/arm64, linux/amd64")] == [
        "linux/amd64", "linux/arm64",
    ]


@pytest.mark.parametrize(
    ("members", "missing_or_extra"),
    [
        ((_member("amd64"),), "linux/arm64"),  # build dropped a platform: the #672 gap, re-opened
        ((_member("amd64"), _member("arm64"), _member("ppc64le")), "linux/ppc64le"),
    ],
)
def test_require_refuses_an_index_that_differs_from_the_built_set(members, missing_or_extra):
    with pytest.raises(vm.MatrixError, match=missing_or_extra):
        vm.matrix(_index(*members), require="linux/amd64,linux/arm64")


def test_every_runner_is_a_native_hosted_label():
    # The smoke test needs native Linux Docker (ADR-P041); an emulated leg is not a verification.
    assert vm.RUNNERS == {"linux/amd64": "ubuntu-latest", "linux/arm64": "ubuntu-24.04-arm"}


def _cli(stdin: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(_SCRIPT), *args], input=stdin, capture_output=True,
                          text=True, check=False)


def test_cli_prints_compact_json_for_github_output():
    proc = _cli(json.dumps(_index(_member("amd64"), _attestation())))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == 'matrix=[{"platform":"linux/amd64","arch":"amd64","runner":"ubuntu-latest"}]\n'


@pytest.mark.parametrize("stdin", ["", "not json", "[]"])
def test_cli_fails_closed_on_unreadable_input(stdin):
    proc = _cli(stdin)
    assert proc.returncode == 1
    assert proc.stdout == "", "a refusal must never write a matrix line"
    assert proc.stderr.startswith("::error title=verify matrix::")


def test_cli_refusal_is_a_workflow_error_annotation():
    proc = _cli(json.dumps(_index(_member("arm", variant="v7"))))
    assert proc.returncode == 1
    assert proc.stderr.startswith("::error title=verify matrix::")


# ---- the CLI's `--require` path: the exact argv build-verify-promote.yml's `resolve` passes -------

_BUILT = "linux/amd64,linux/arm64"


def test_cli_require_admits_an_index_carrying_exactly_the_built_set():
    proc = _cli(json.dumps(_index(_member("amd64"), _attestation(), _member("arm64"), _attestation())),
                "--require", _BUILT)
    assert proc.returncode == 0, proc.stderr
    rows = json.loads(proc.stdout.removeprefix("matrix="))
    assert [r["platform"] for r in rows] == ["linux/amd64", "linux/arm64"]


def test_cli_require_refuses_a_short_index_with_no_matrix_line():
    # The #672 gap itself: a build that silently dropped arm64 must redden, not promote amd64 alone.
    proc = _cli(json.dumps(_index(_member("amd64"), _attestation())), "--require", _BUILT)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "missing ['linux/arm64']" in proc.stderr


@pytest.mark.parametrize(
    "argv", [("--require",), ("--bogus",), ("--require", _BUILT, "extra"), ("linux/amd64",)]
)
def test_cli_refuses_a_malformed_argv_with_no_matrix_line(argv):
    # Fail closed: a misparsed `--require` that fell through to "no requirement" would quietly turn
    # the refusal above off.
    proc = _cli(json.dumps(_index(_member("amd64"))), *argv)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert proc.stderr.startswith("::error title=verify matrix::usage")


@pytest.mark.parametrize("require", ["", " "])
def test_cli_an_empty_require_is_no_requirement(require):
    proc = _cli(json.dumps(_index(_member("amd64"))), "--require", require)
    assert proc.returncode == 0, proc.stderr


def test_a_platform_listed_twice_is_one_leg():
    rows = vm.matrix(_index(_member("amd64"), _member("amd64"), _attestation()), _BUILT.split(",")[0])
    assert rows == [{"platform": "linux/amd64", "arch": "amd64", "runner": "ubuntu-latest"}]


def test_a_multi_line_refusal_stays_one_annotation():
    # stdout feeds $GITHUB_OUTPUT and stderr a workflow command; a raw newline would end the
    # annotation early and leak the rest as plain log text.
    assert vm._escape("a%b\r\nc") == "a%25b%0D%0Ac"
