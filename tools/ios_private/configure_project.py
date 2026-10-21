#!/usr/bin/env python3
"""Build-host-only overlay; generated game sources stay under ignored gen/."""
import argparse
from pathlib import Path
import yaml

def main():
    parser = argparse.ArgumentParser(description="Configure XcodeGen project overlay for iOS")
    parser.add_argument(
        "--mode",
        choices=["auto", "startup", "all"],
        default="auto",
        help="Overlay mode: 'startup' (gen/ios-private entry probe), 'all' (gen/all 128 shards), or 'auto'",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output YAML file path (default: ios/project-private.yml)",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]

    # Resolve mode
    mode = args.mode
    if mode == "auto":
        if (root / "gen/ios-private/startup_probe.c").is_file():
            mode = "startup"
        elif (root / "gen/all/shard_0000.c").is_file():
            mode = "all"
        else:
            mode = "startup"  # default to checking startup files

    spec = yaml.safe_load((root / "ios/project.yml").read_text(encoding="utf-8"))
    target = spec["targets"]["NFSU2iOS"]

    if mode == "startup":
        required = ["lifted.c", "private_probe.c", "startup_lifted.c", "startup_probe.c", "manifest.json"]
        for filename in required:
            if not (root / "gen/ios-private" / filename).is_file():
                raise SystemExit(f"private generation is required; no stub fallback (missing gen/ios-private/{filename})")
        target["sources"].extend(
            {"path": "../gen/ios-private/" + name}
            for name in ["lifted.c", "private_probe.c", "startup_lifted.c", "startup_probe.c"]
        )
        current_defs = target["settings"]["base"].get("GCC_PREPROCESSOR_DEFINITIONS", ["$(inherited)"])
        target["settings"]["base"]["GCC_PREPROCESSOR_DEFINITIONS"] = list(
            dict.fromkeys(current_defs + ["NFS_PRIVATE_PROBE=1", "NFS_PRIVATE_STARTUP=1"])
        )
    elif mode == "all":
        if not (root / "gen/all/shard_0000.c").is_file():
            raise SystemExit("gen/all shards not found; run tools/genall.py first")
        target["sources"].append({"path": "../gen/all"})
        current_defs = target["settings"]["base"].get("GCC_PREPROCESSOR_DEFINITIONS", ["$(inherited)"])
        target["settings"]["base"]["GCC_PREPROCESSOR_DEFINITIONS"] = list(
            dict.fromkeys(current_defs + ["NFS_ALL_SHARDS=1"])
        )

    # Header search paths
    current_hsp = target["settings"]["base"].get("HEADER_SEARCH_PATHS", ["$(inherited)", "$(SRCROOT)/../runtime"])
    extra_hsp = ["$(SRCROOT)/../runtime", "$(SRCROOT)/NFSU2iOS/Native"]
    if mode == "all":
        extra_hsp.append("$(SRCROOT)/../gen/all")
    target["settings"]["base"]["HEADER_SEARCH_PATHS"] = list(dict.fromkeys(current_hsp + extra_hsp))

    # Version metadata
    target["info"]["properties"]["CFBundleShortVersionString"] = "0.17.0"
    target["info"]["properties"]["CFBundleVersion"] = "24"

    # Destination output file
    out_path = Path(args.out) if args.out else (root / "ios/project-private.yml")
    out_path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8", newline="\n")
    print(f"Configured {out_path.name} in '{mode}' mode (v0.17.0, build 24)")

if __name__ == "__main__":
    main()
