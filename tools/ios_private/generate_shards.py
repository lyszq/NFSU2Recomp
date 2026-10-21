#!/usr/bin/env python3
"""Generate and attest the private full-runtime iOS shard set.

The generated C contains game code and must remain under the repository's
ignored ``gen/`` tree.  This follows the v2 generation settings in
``tools/uret_v2.sh`` and invokes the repository's actual generators for the
shards, flag ABI data, relocations, and import argument table.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_EXE_SHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"
EXPECTED_EXE_SIZE = 4788224
FULL_RUNTIME_SHARDS = 128
MANIFEST_NAME = "ios-full-manifest.json"

_REPRODUCIBLE_ENV_KEYS = (
    "GENOUT",
    "OVERRIDE",
    "FLAGABI",
    "X87OPT",
    "RETEIP",
    "MEMARG",
    "INLINE",
    "HOOKS",
    "WATCH",
    "COVERAGE",
    "COMMENTS",
    "FCMPBL",
    "FLAGOPT",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _validate_executable(exe_path: Path, root: Path = ROOT) -> dict[str, Any]:
    exe_path = exe_path.resolve()
    if not exe_path.is_file():
        raise FileNotFoundError(f"Executable not found: {exe_path}")
    size = exe_path.stat().st_size
    digest = _sha256(exe_path)
    if size != EXPECTED_EXE_SIZE or digest != EXPECTED_EXE_SHA256:
        raise ValueError(
            "Unsupported or unauthenticated SPEED2.EXE "
            f"(size={size}, sha256={digest})"
        )
    return {"path": _relative(exe_path, root), "size_bytes": size, "sha256": digest}


def _read_override_addresses(root: Path = ROOT) -> list[str]:
    """Read the exact override set used by the v2 desktop generation recipe."""
    recipe = root / "tools" / "uret_v2.sh"
    text = recipe.read_text(encoding="utf-8")
    match = re.search(r"(?m)^OVR=([0-9a-fA-F,]+)[ \t]*$", text)
    if not match:
        raise RuntimeError(f"Could not find the OVR list in {recipe}")
    raw = [part.strip().lower().removeprefix("0x") for part in match.group(1).split(",")]
    if not raw or any(not re.fullmatch(r"[0-9a-f]{1,8}", part) for part in raw):
        raise RuntimeError(f"Invalid override list in {recipe}")
    if len(set(raw)) != len(raw):
        raise RuntimeError(f"Duplicate override addresses in {recipe}")
    return [f"{int(address, 16):08x}" for address in raw]


def _tool_provenance(root: Path) -> dict[str, dict[str, Any]]:
    paths = (
        "tools/uret_v2.sh",
        "tools/ios_private/generate_shards.py",
        "tools/ios_private/configure_project.py",
        "tools/genall.py",
        "tools/lift.py",
        "tools/reloc2.py",
        "tools/flagabi.py",
        "tools/argcount.py",
        "runtime/overrides.c",
        "runtime/d3dx_hle.c",
    )
    result: dict[str, dict[str, Any]] = {}
    for relative in paths:
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(f"Required generation provenance file is missing: {relative}")
        result[relative] = {"size_bytes": path.stat().st_size, "sha256": _sha256(path)}
    return result


def _source_revision(root: Path) -> tuple[str, bool]:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True,
        capture_output=True, text=True,
    )
    revision = result.stdout.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("Could not determine the exact 40-character source HEAD SHA")
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, check=True,
        capture_output=True, text=True,
    )
    return revision, bool(status.stdout.strip())


def _generation_environment(out_dir: Path, override_addresses: list[str], flagabi_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in _REPRODUCIBLE_ENV_KEYS:
        env.pop(key, None)
    env.update(
        {
            "GENOUT": str(out_dir),
            "OVERRIDE": ",".join(override_addresses),
            "FLAGABI": str(flagabi_path),
            "X87OPT": "1",
            "RETEIP": "0",
            "MEMARG": "1",
        }
    )
    return env


def _run_generator(root: Path, exe_path: Path, nshard: int, out_dir: Path,
                   env: dict[str, str]) -> dict[str, Any]:
    """Import genall only after its generation environment has been fixed."""
    tools_dir = str(root / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    # genall reads OVERRIDE and MEMARG at import time. Reloading keeps repeated
    # in-process calls deterministic and makes inherited settings irrelevant.
    sys.modules.pop("genall", None)
    previous = {key: os.environ.get(key) for key in _REPRODUCIBLE_ENV_KEYS}
    previous_path = list(sys.path)
    try:
        for key in _REPRODUCIBLE_ENV_KEYS:
            os.environ.pop(key, None)
        os.environ.update({key: env[key] for key in _REPRODUCIBLE_ENV_KEYS if key in env})
        module = importlib.import_module("genall")
        return module.generate_shards(
            exe=str(exe_path), nshard=nshard, out=str(out_dir)
        )
    finally:
        sys.modules.pop("genall", None)
        sys.path[:] = previous_path
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _generate_impargs(root: Path, exe_path: Path, out_dir: Path,
                       relocations: Path, env: dict[str, str]) -> None:
    """Run argcount.py in a small private staging cwd because it writes gen/all."""
    # argcount.py's output path is fixed at gen/all/impargs.c. Run the real
    # script with a staged tools/lift.py and reloc table, then copy that output
    # into the requested ignored gen/ directory. This avoids touching a second
    # source tree or changing the authoritative generator.
    with tempfile.TemporaryDirectory(prefix="ios-full-impargs-", dir=str(out_dir.parent)) as temp:
        staging = Path(temp)
        (staging / "tools").mkdir()
        (staging / "out").mkdir()
        (staging / "gen" / "all").mkdir(parents=True)
        shutil.copy2(root / "tools" / "lift.py", staging / "tools" / "lift.py")
        shutil.copy2(relocations, staging / "out" / "relocs.txt")
        staged_env = env.copy()
        staged_env.pop("GENOUT", None)
        subprocess.run(
            [sys.executable, str(root / "tools" / "argcount.py"), str(exe_path)],
            cwd=staging,
            env=staged_env,
            check=True,
        )
        generated = staging / "gen" / "all" / "impargs.c"
        if not generated.is_file() or generated.stat().st_size == 0:
            raise RuntimeError("argcount.py did not produce gen/all/impargs.c")
        shutil.copy2(generated, out_dir / "impargs.c")


def _expected_output_names(nshard: int) -> list[str]:
    return (
        [f"shard_{index:04d}.c" for index in range(nshard)]
        + ["stubs.c", "fntab.c", "decls.h", "impargs.c"]
    )


def _check_generated_outputs(out_dir: Path, nshard: int,
                             summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if nshard != FULL_RUNTIME_SHARDS:
        raise ValueError(f"The full iOS runtime requires exactly {FULL_RUNTIME_SHARDS} shards")
    if summary.get("shards") != FULL_RUNTIME_SHARDS:
        raise RuntimeError(f"Generator reported an unexpected shard count: {summary.get('shards')}")
    function_count = summary.get("function_count")
    defined_count = summary.get("defined_count")
    missing_count = summary.get("missing_count")
    if not all(isinstance(value, int) and value >= 0
               for value in (function_count, defined_count, missing_count)):
        raise RuntimeError("Generator returned invalid function counts")
    if defined_count + missing_count != function_count:
        raise RuntimeError("Generator function counts do not add up")

    fntab_path = out_dir / "fntab.c"
    fntab = fntab_path.read_text(encoding="utf-8")
    count_match = re.search(r"\bg_fn_count\s*=\s*(\d+)\s*;", fntab)
    if not count_match or int(count_match.group(1)) != function_count:
        raise RuntimeError("fntab.c function count does not match the generator summary")
    stubs = (out_dir / "stubs.c").read_text(encoding="utf-8")
    stub_count = len(re.findall(r"\bvoid\s+sub_[0-9a-fA-F]{8}\s*\(", stubs))
    if stub_count != missing_count:
        raise RuntimeError(
            f"stubs.c has {stub_count} fallback definitions; generator reported {missing_count}"
        )
    impargs = (out_dir / "impargs.c").read_text(encoding="utf-8")
    import_count_match = re.search(r"\bg_imp_count\s*=\s*(\d+)\s*;", impargs)
    if not import_count_match:
        raise RuntimeError("impargs.c is missing g_imp_count")

    files: dict[str, dict[str, Any]] = {}
    for filename in _expected_output_names(nshard):
        path = out_dir / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"Missing or empty generated output: {filename}")
        files[filename] = {"size_bytes": path.stat().st_size, "sha256": _sha256(path)}
    return files


def _write_manifest(out_dir: Path, source: dict[str, Any], override_addresses: list[str],
                    env: dict[str, str], summary: dict[str, Any],
                    files: dict[str, dict[str, Any]], provenance: dict[str, Any],
                    intermediates: dict[str, dict[str, Any]], root: Path) -> Path:
    source_commit, source_dirty = _source_revision(root)
    manifest = {
        "schema_version": 1,
        "artifact": "NFSU2 iOS full-runtime generated sources",
        "source_commit": source_commit,
        "source_dirty": source_dirty,
        "source": source,
        "config": {
            "shard_count": FULL_RUNTIME_SHARDS,
            "override_addresses": override_addresses,
            "environment": {
                key: env[key]
                for key in ("X87OPT", "RETEIP", "MEMARG")
            },
            "override_source": "tools/uret_v2.sh:OVR",
            "argument_table_generator": "tools/argcount.py",
        },
        "summary": {
            "function_count": summary["function_count"],
            "defined_count": summary["defined_count"],
            "missing_count": summary["missing_count"],
            "shards": summary["shards"],
            "bytes": summary.get("bytes"),
            "traps": summary.get("traps"),
            "truncated": summary.get("truncated"),
            "import_count": int(re.search(
                r"\bg_imp_count\s*=\s*(\d+)\s*;",
                (out_dir / "impargs.c").read_text(encoding="utf-8"),
            ).group(1)),
        },
        "provenance": {**provenance, "generated_inputs": intermediates},
        "files": files,
    }
    destination = out_dir / MANIFEST_NAME
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def generate_ios_shards(exe_path: str | Path,
                        nshard: int = FULL_RUNTIME_SHARDS,
                        out_dir: str | Path | None = None,
                        root: Path = ROOT) -> dict[str, Any]:
    """Generate 128 full-runtime shards and a hash-bound private manifest."""
    root = Path(root).resolve()
    exe_path = Path(exe_path).resolve()
    if nshard != FULL_RUNTIME_SHARDS:
        raise ValueError(f"The full iOS runtime requires exactly {FULL_RUNTIME_SHARDS} shards")
    source = _validate_executable(exe_path, root)
    out_dir = (root / "gen" / "all") if out_dir is None else Path(out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir = out_dir.resolve()
    try:
        out_dir.relative_to((root / "gen").resolve())
    except ValueError as exc:
        raise ValueError("Generated game C must stay inside the ignored repository gen/ directory") from exc
    out_dir.mkdir(parents=True, exist_ok=True)

    out_root = root / "out"
    out_root.mkdir(parents=True, exist_ok=True)
    relocations = out_root / "relocs.txt"
    flagabi_path = out_root / "flagabi.json"
    override_addresses = _read_override_addresses(root)
    env = _generation_environment(out_dir, override_addresses, flagabi_path)

    subprocess.run(
        [sys.executable, str(root / "tools" / "reloc2.py"), str(exe_path)],
        cwd=root, env=env, check=True,
    )
    if not relocations.is_file() or relocations.stat().st_size == 0:
        raise RuntimeError("reloc2.py did not produce out/relocs.txt")
    subprocess.run(
        [sys.executable, str(root / "tools" / "flagabi.py"), str(exe_path), str(flagabi_path)],
        cwd=root, env=env, check=True,
    )
    if not flagabi_path.is_file() or flagabi_path.stat().st_size == 0:
        raise RuntimeError("flagabi.py did not produce out/flagabi.json")

    summary = _run_generator(root, exe_path, nshard, out_dir, env)
    _generate_impargs(root, exe_path, out_dir, relocations, env)
    files = _check_generated_outputs(out_dir, nshard, summary)
    provenance = _tool_provenance(root)
    intermediates = {
        "out/relocs.txt": {"size_bytes": relocations.stat().st_size, "sha256": _sha256(relocations)},
        "out/flagabi.json": {"size_bytes": flagabi_path.stat().st_size, "sha256": _sha256(flagabi_path)},
    }
    manifest_path = _write_manifest(
        out_dir, source, override_addresses, env, summary, files, provenance, intermediates, root
    )
    print(
        f"\n[iOS full-runtime generation] {summary['shards']} shards, "
        f"{summary['function_count']} functions, {summary['missing_count']} fallback stubs"
    )
    print(f"[iOS full-runtime generation] private manifest: {manifest_path}")
    return {"summary": summary, "manifest": str(manifest_path), "source": source, "files": files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the authenticated 128-shard iOS full-runtime source set"
    )
    parser.add_argument(
        "--exe", type=Path, default=ROOT / "out" / "private" / "SPEED2.EXE",
        help="Authenticated SPEED2.EXE (default: out/private/SPEED2.EXE)",
    )
    parser.add_argument(
        "--shards", type=int, default=FULL_RUNTIME_SHARDS,
        help="Shard count; full-runtime iOS generation requires exactly 128",
    )
    parser.add_argument(
        "--out", type=Path, default=ROOT / "gen" / "all",
        help="Ignored output directory under gen/ (default: gen/all)",
    )
    args = parser.parse_args(argv)
    generate_ios_shards(args.exe, args.shards, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
