#!/usr/bin/env python3
"""Compile and run the Swift storage regression using disposable synthetic files."""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dest", type=Path, help="writable directory for temporary Swift build files")
    args = parser.parse_args()

    if platform.system() != "Darwin":
        print("ERROR: this native Swift storage regression must run on macOS.", file=sys.stderr)
        return 2

    swiftc = shutil.which("swiftc")
    if swiftc is None:
        print("ERROR: swiftc was not found; no storage regression was run.", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[1]
    game_file_state = repo_root / "ios" / "NFSU2iOS" / "GameFileState.swift"
    fixture = Path(__file__).with_name("ios_file_storage_fixture.swift")
    if not game_file_state.is_file() or not fixture.is_file():
        print("ERROR: GameFileState.swift or its Swift fixture is missing.", file=sys.stderr)
        return 2

    destination = args.dest.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="nfsu2-file-storage-", dir=destination) as temporary:
        temporary_root = Path(temporary)
        combined_source = temporary_root / "ios_file_storage_regression.swift"
        executable = temporary_root / "ios_file_storage_regression"
        synthetic_files = temporary_root / "synthetic-files"
        combined_source.write_text(
            game_file_state.read_text(encoding="utf-8")
            + "\n\n"
            + fixture.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        command = [
            swiftc,
            "-D",
            "NFS_FULL_RUNTIME",
            "-parse-as-library",
            "-swift-version",
            "5",
            "-target",
            platform.machine() + "-apple-macosx12.0",
            str(combined_source),
            "-o",
            str(executable),
        ]
        compiled = subprocess.run(command, text=True, capture_output=True, check=False)
        if compiled.stdout:
            print(compiled.stdout, end="")
        if compiled.stderr:
            print(compiled.stderr, end="", file=sys.stderr)
        if compiled.returncode != 0:
            return compiled.returncode

        result = subprocess.run(
            [str(executable), str(synthetic_files)],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
