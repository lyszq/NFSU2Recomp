#!/usr/bin/env python3
"""Build-host-only overlay; generated game sources stay under ignored gen/."""
from pathlib import Path
import yaml

root = Path(__file__).resolve().parents[2]
for filename in ["lifted.c", "private_probe.c", "startup_lifted.c", "startup_probe.c", "manifest.json"]:
    if not (root / "gen/ios-private" / filename).is_file():
        raise SystemExit("private generation is required; no stub fallback")
spec = yaml.safe_load((root / "ios/project.yml").read_text(encoding="utf-8"))
target = spec["targets"]["NFSU2iOS"]
target["sources"].extend({"path": "../gen/ios-private/" + name}
                         for name in ["lifted.c", "private_probe.c", "startup_lifted.c", "startup_probe.c"])
current_hsp = target["settings"]["base"].get("HEADER_SEARCH_PATHS", ["$(inherited)", "$(SRCROOT)/../runtime"])
target["settings"]["base"]["HEADER_SEARCH_PATHS"] = list(dict.fromkeys(current_hsp + ["$(SRCROOT)/../runtime", "$(SRCROOT)/NFSU2iOS/Native"]))
current_defs = target["settings"]["base"].get("GCC_PREPROCESSOR_DEFINITIONS", ["$(inherited)"])
target["settings"]["base"]["GCC_PREPROCESSOR_DEFINITIONS"] = list(dict.fromkeys(current_defs + ["NFS_PRIVATE_PROBE=1", "NFS_PRIVATE_STARTUP=1"]))
target["info"]["properties"]["CFBundleShortVersionString"] = "0.12.0"
target["info"]["properties"]["CFBundleVersion"] = "18"
(root / "ios/project-private.yml").write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8", newline="\n")
