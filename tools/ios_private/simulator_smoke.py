#!/usr/bin/env python3
"""Exercise production full-runtime controls in a disposable private simulator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
from provision import EXPECTED_SHA
from verify_simulator_smoke import inspect

BUNDLE = 'dev.lyszq.nfsu2ios'

def select_device(inventory):
    candidates = []
    for runtime, devices in inventory['devices'].items():
        match = re.search(r'\.iOS-(\d+)-(\d+)(?:-(\d+))?$', runtime)
        if not match:
            continue
        version = tuple(int(v or 0) for v in match.groups())
        for device in devices:
            if device.get('isAvailable') and 'iPad' in device['name']:
                candidates.append((version, device['name'], runtime, device))
    if not candidates:
        raise ValueError('no available iPad iOS Simulator runtime; no device validation inferred')
    _, _, runtime, device = sorted(candidates, key=lambda c: c[:2], reverse=True)[0]
    if not re.fullmatch(r'[A-Fa-f0-9-]{36}', device['udid']):
        raise ValueError('invalid simulator UUID')
    return {'udid': device['udid'], 'name': device['name'], 'runtime': runtime}

def capture(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()

def run_tests(command, log_path, timeout=240):
    with log_path.open('w') as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
            raise TimeoutError('full-runtime simulator UI test exceeded its 240-second bound')
        if code:
            raise subprocess.CalledProcessError(code, command)

def smoke(a):
    data = a.exe.read_bytes()
    if len(data) != 4788224 or hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise ValueError('unsupported simulator input; no staging performed')
    if not re.fullmatch('[a-f0-9]{40}', a.source):
        raise ValueError('exact source SHA required')
    a.out.mkdir(parents=True, exist_ok=True)
    app = a.derived / 'Build/Products/Release-iphonesimulator/NFSU2iOS.app'
    tests = list((a.derived / 'Build/Products').glob('*.xctestrun'))
    if not app.is_dir() or len(tests) != 1:
        raise ValueError('one complete build-for-testing product is required')
    subprocess.run(['xcrun', 'simctl', 'install', a.device, str(app)], check=True, timeout=60)
    subprocess.run(['xcrun', 'simctl', 'terminate', a.device, BUNDLE], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    container = Path(capture('xcrun', 'simctl', 'get_app_container', a.device, BUNDLE, 'data'))
    game = container / 'Library/Application Support/NFSU2/Game'
    game.mkdir(parents=True, exist_ok=True)
    (game / 'SPEED2.EXE').write_bytes(data)
    (game / 'CI-ASSETS-INTENTIONALLY-ABSENT.txt').write_text(
        'Negative-input test: real game assets are intentionally absent. Not a game file.\n')
    # The production logger appends. A previous attempt must never satisfy the
    # source/entry gate for this run. Only this disposable CI app's log is reset.
    (container / 'Documents/NFSU2Runtime.log').unlink(missing_ok=True)
    started = time.monotonic()
    try:
        run_tests(['xcodebuild', 'test-without-building', '-xctestrun', str(tests[0]),
                   '-destination', 'id=' + a.device, '-parallel-testing-enabled', 'NO',
                   '-test-timeouts-enabled', 'YES', '-maximum-test-execution-time-allowance', '150',
                   '-resultBundlePath', str(a.out / 'FullRuntimeSmoke.xcresult')],
                  a.out / 'simulator-test.log')
    finally:
        try:
            current = Path(capture('xcrun', 'simctl', 'get_app_container', a.device, BUNDLE, 'data'))
            native_log = current / 'Documents/NFSU2Runtime.log'
            if native_log.is_file():
                shutil.copy2(native_log, a.out / 'NFSU2Runtime-simulator.log')
        finally:
            try:
                subprocess.run(['xcrun', 'simctl', 'io', a.device, 'screenshot',
                                str(a.out / 'simulator-scene-unverified.png')], check=False, timeout=30)
            finally:
                subprocess.run(['xcrun', 'simctl', 'terminate', a.device, BUNDLE], check=False, timeout=30)
    log = a.out / 'NFSU2Runtime-simulator.log'
    report = inspect(log.read_text(errors='replace'), a.source)
    report.update(ui_test_passed=True, simulator_udid=a.device,
                  elapsed_seconds=round(time.monotonic() - started, 3),
                  runtime_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
    (a.out / 'simulator-smoke-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS | actual full runtime Start and scene resume; missing-assets iOS Simulator smoke only')

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='mode', required=True)
    select = sub.add_parser('select')
    select.add_argument('--out', type=Path, required=True)
    run = sub.add_parser('run')
    run.add_argument('--device', required=True)
    run.add_argument('--exe', type=Path, required=True)
    run.add_argument('--derived', type=Path, required=True)
    run.add_argument('--source', required=True)
    run.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    if a.mode == 'select':
        inventory = json.loads(capture('xcrun', 'simctl', 'list', 'devices', 'available', '-j'))
        device = select_device(inventory)
        a.out.write_text(json.dumps(device, indent=2) + '\n')
        subprocess.run(['xcrun', 'simctl', 'boot', device['udid']], check=False)
        subprocess.run(['xcrun', 'simctl', 'bootstatus', device['udid'], '-b'], check=True, timeout=240)
        print(device['udid'])
        if os.environ.get('GITHUB_ENV'):
            with Path(os.environ['GITHUB_ENV']).open('a') as env:
                env.write('NFS_SIMULATOR_UDID=' + device['udid'] + '\n')
    else:
        smoke(a)

if __name__ == '__main__':
    main()
