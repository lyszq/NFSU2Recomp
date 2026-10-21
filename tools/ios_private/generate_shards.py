#!/usr/bin/env python3
"""iOS Private 128-shard recompilation generator.

Extracts all functions from the authenticated SPEED2.EXE, lifts them to C,
and partitions them into 128 compilation shards in gen/all/ along with
fntab.c, stubs.c, and decls.h.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
SHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"
EXE_SIZE = 4788224

def generate_ios_shards(exe_path, nshard=128, out_dir=None):
    exe_path = Path(exe_path).resolve()
    if not exe_path.is_file():
        raise FileNotFoundError(f"Executable not found: {exe_path}")
    
    blob = exe_path.read_bytes()
    if len(blob) != EXE_SIZE or hashlib.sha256(blob).hexdigest() != SHA256:
        raise ValueError("Unsupported or unauthenticated SPEED2.EXE binary")
    
    if out_dir is None:
        out_dir = ROOT / "gen" / "all"
    else:
        out_dir = Path(out_dir).resolve()
    
    out_dir.mkdir(parents=True, exist_ok=True)
    
    sys.path.insert(0, str(ROOT / "tools"))
    from genall import generate_shards
    
    summary = generate_shards(exe=str(exe_path), nshard=nshard, out=str(out_dir))
    
    # Verify outputs
    expected_files = [f"shard_{i:04d}.c" for i in range(nshard)] + ["stubs.c", "fntab.c", "decls.h"]
    missing_files = []
    for fn in expected_files:
        p = out_dir / fn
        if not p.is_file() or p.stat().st_size == 0:
            missing_files.append(fn)
            
    if missing_files:
        raise RuntimeError(f"Missing or empty expected shard outputs: {missing_files}")
    
    print(f"\n[iOS Shard Pipeline] Successfully generated {nshard} shards, stubs.c, fntab.c, and decls.h in {out_dir}")
    print(f"Total functions: {summary['function_count']} (defined: {summary['defined_count']}, missing: {summary['missing_count']})")
    return summary

def main():
    parser = argparse.ArgumentParser(description="Generate 128 iOS compilation shards from SPEED2.EXE")
    parser.add_argument("--exe", type=Path, default=ROOT / "out" / "private" / "SPEED2.EXE", help="Path to SPEED2.EXE")
    parser.add_argument("--shards", type=int, default=128, help="Number of shards to generate (default: 128)")
    parser.add_argument("--out", type=Path, default=ROOT / "gen" / "all", help="Output directory (default: gen/all)")
    args = parser.parse_args()
    
    generate_ios_shards(args.exe, args.shards, args.out)

if __name__ == "__main__":
    main()
