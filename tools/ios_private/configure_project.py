#!/usr/bin/env python3
"""Build-host-only overlay; generated game sources stay under ignored gen/."""
from pathlib import Path
import yaml

root = Path(__file__).resolve().parents[2]
for filename in ["lifted.c", "private_probe.c", "manifest.json"]:
    if not (root / "gen/ios-private" / filename).is_file():
        raise SystemExit("private generation is required; no stub fallback")
spec = yaml.safe_load((root / "ios/project.yml").read_text())
target = spec["targets"]["NFSU2iOS"]
target["sources"].extend({"path": "../gen/ios-private/" + name}
                         for name in ["lifted.c", "private_probe.c"])
target["settings"]["base"]["GCC_PREPROCESSOR_DEFINITIONS"] = ["$(inherited)", "NFS_PRIVATE_PROBE=1"]
target["info"]["properties"]["CFBundleShortVersionString"] = "0.4.1"
target["info"]["properties"]["CFBundleVersion"] = "5"
(root / "ios/project-private.yml").write_text(yaml.safe_dump(spec, sort_keys=False))
