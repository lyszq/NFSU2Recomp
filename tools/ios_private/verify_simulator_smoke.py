#!/usr/bin/env python3
"""Record narrowly scoped native simulator evidence after successful XCUITest."""
import argparse
import hashlib
import json
from pathlib import Path
import re

def inspect(log: str, source: str):
    if not re.fullmatch('[a-f0-9]{40}', source):
        raise ValueError('exact compiled source required')
    if not re.search(r'runtime_source_sha=' + re.escape(source) + r'(?:\s|$)', log):
        raise ValueError('native log source pin differs')
    if 'runtime guest entry begin: eip=0x0075bcc7' not in log:
        raise ValueError('actual guest entry invocation was not observed')
    return {'compiled_source': source, 'platform': 'iOS Simulator',
            'input': 'authenticated SPEED2.EXE; game assets intentionally absent',
            'actual_entry_invocation_observed': True,
            'game_boot': False, 'real_game_frame': False,
            'gameplay_audio': False, 'playable_race': False,
            'arm64_device_validation': 'not performed',
            'scope': 'production Start UI and foreground/background responsiveness; missing-assets negative-input smoke only'}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--log', type=Path, required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    data = a.log.read_bytes()
    report = inspect(data.decode('utf-8', errors='replace'), a.source)
    report['runtime_log_sha256'] = hashlib.sha256(data).hexdigest()
    a.out.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS | actual full-runtime entry called on iOS Simulator; assets absent, device gameplay unverified')

if __name__ == '__main__':
    main()
