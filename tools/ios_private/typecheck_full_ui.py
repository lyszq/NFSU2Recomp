#!/usr/bin/env python3
"""Typecheck the production full-runtime Swift branch without any game input."""
import subprocess
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    app = root / 'ios/NFSU2iOS'
    sdk = subprocess.check_output(
        ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    sources = sorted(str(path) for path in app.rglob('*.swift')
                     if path.name != 'MetalPreview.swift')
    subprocess.run([
        'xcrun', '--sdk', 'iphoneos', 'swiftc', '-typecheck', '-parse-as-library',
        '-swift-version', '5', '-target', 'arm64-apple-ios16.0', '-sdk', sdk,
        '-D', 'NFS_FULL_RUNTIME', '-Xcc', '-DNFS_FULL_RUNTIME=1',
        '-I', str(root / 'runtime'), '-I', str(app / 'Native'),
        '-import-objc-header', str(app / 'Native/NFSU2BridgingHeader.h'),
        *sources,
    ], check=True, cwd=root, timeout=180)
    print('PASS | full-runtime production Swift UI typechecks for iOS ARM64; no game input or runtime execution')


if __name__ == '__main__':
    main()
