import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / 'tools/ios_private').exists():
    for candidate in [ROOT / 'NFSU2-iOS-v02-one-click-update/NFSU2Recomp-v02', ROOT.parent / 'NFSU2-iOS-v02-one-click-update/NFSU2Recomp-v02']:
        if (candidate / 'tools/ios_private').exists():
            ROOT = candidate
            break
sys.path.insert(0, str(ROOT / 'tools/ios_private'))
from provision import GitHub

p = argparse.ArgumentParser()
p.add_argument('--delivery', type=Path, required=True)
p.add_argument('--run', type=int, required=True)
p.add_argument('--public-run', type=int, required=True)
p.add_argument('--source', required=True)
a = p.parse_args()
client = GitHub('NFSU2Recomp-ios-private')
client.private()
private = client.api(f'/repos/{client.repository}/actions/runs/{a.run}')
jobs = client.api(f'/repos/{client.repository}/actions/runs/{a.run}/jobs')['jobs']
public = client.api(f'/repos/lyszq/NFSU2Recomp/actions/runs/{a.public_run}')
assert private['conclusion'] == public['conclusion'] == 'success'
assert public['head_sha'] == a.source and all(j['conclusion'] == 'success' for j in jobs)
workflow = client.api(f'/repos/{client.repository}/contents/.github/workflows/ios-private.yml?ref={private["head_sha"]}')
assert f'SOURCE_SHA: {a.source}' in base64.b64decode(workflow['content']).decode()
paths = client.api(f'/repos/{client.repository}/git/trees/{private["head_sha"]}?recursive=1')['tree']
assert sorted(x['path'] for x in paths if x['type'] == 'blob') == ['.github/workflows/ios-private.yml', 'README.md']
release = client.api(f'/repos/{client.repository}/releases/tags/private-input-v1')
assets = release['assets']
assert len(assets) == 1 and assets[0]['name'] == 'SPEED2.EXE'
assert assets[0]['size'] == 4788224 and assets[0]['digest'] == 'sha256:8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297'

manifest = json.loads((a.delivery / 'private-provenance.json').read_text())
reference = manifest['startup']['reference']
assert reference['instructions'] == 192955 and reference['raw_instructions'] == 218676
assert reference['calls'] == 10541 and reference['maximum_depth'] == 12 and reference['api_call_count'] == 884
assert reference['critical_section_count'] == 15
assert reference['tls_slot_count'] == reference['tls_thread_count'] == 1
assert reference['virtual_tsc_profile'] == 'deterministic_entry_tsc_v1'
assert reference['virtual_tsc_initial'] == 1000000 and reference['virtual_tsc_increment'] == 1000
assert reference['rdtsc_calls'] == [{
    'address': 0x006de715,
    'value': 1000000,
    'profile': 'deterministic_entry_tsc_v1',
}]
assert reference['virtual_tsc_next'] == 1001000
assert reference['virtual_tsc_hash'] == 1459213057555500656
assert reference['clock_profile'] == 'deterministic_entry_clock_v1'
expected_clock = {
    'mode': 1,
    'frequency': 1000000,
    'next': 1014000,
    'increment': 1000,
    'query_count': 15,
    'sample_count': 14,
    'trace_hash': 7840025728631253069,
}
assert reference['clock'] == expected_clock
assert all(type(value) is int for value in reference['clock'].values())
assert reference['toolhelp_snapshots'] == {}
observed_targets = list(dict.fromkeys(
    event['target'] for event in reference['direct_calls'] + reference['indirect_jumps']))
assert len(observed_targets) == 1047
assert reference['import_library'] == 'KERNEL32.dll' and reference['import_name'] == 'GetCurrentProcess'
assert reference['cursor_fixture'] == [320,180] and reference['cursor_profile'] == 'deterministic_cursor_fixture_v1'
assert reference['ip'] == 0x006f580f and reference['target'] == 0xf000009b
assert manifest['startup']['generated_functions'] == 1201
assert reference['cpuid_profile'] == 'upstream_static_x86_006d8'
assert [x['leaf'] for x in reference['cpuid_calls']] == [1,0,1,0,1,0x80000001,1]
assert next(x for x in reference['cpuid_calls'] if x['leaf']==0x80000001)['edx'] == 0
assert 'eflags_get(c) & 0x200cd5u' in (ROOT / 'tools/ios_private/startup_probe.c.in').read_text()
assert 'EFLAGS_MASK = 0x200CD5' in (ROOT / 'tools/ios_private/startup_oracle.py').read_text()
assert reference['user_objects'] == {'11599873': {'handle':11599873,'kind':'CURSOR','origin':'SYSTEM_SHARED','system_id':32512,'module':0,'shared':True}}
assert reference['resource_missing_application_icon'] is True
probe_template = (ROOT / 'tools/ios_private/startup_probe.c.in').read_text()
assert 'windows.clock.trace_hash != UINT64_C(@EXPECTED_CLOCK_HASH@)' in probe_template
assert 'const uint32_t expected_snapshots[GUEST_TOOLHELP_SNAPSHOT_LIMIT][4]' in probe_template
assert 'windows.toolhelp.count != @EXPECTED_SNAPSHOT_COUNT@' in probe_template
assert 'for (unsigned i=0; i<GUEST_TOOLHELP_SNAPSHOT_LIMIT; ++i)' in probe_template
strict_test_path = ROOT / 'tests/ios_startup_probe_strict_test.py'
strict_test = ast.parse(strict_test_path.read_text())
rejected_cases = next(
    node.value for node in ast.walk(strict_test)
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'rejected'
            for target in node.targets))
assert isinstance(rejected_cases, ast.List) and len(rejected_cases.elts) == 16
startup_doc = (ROOT / 'docs/ios-startup-v019.md').read_text()
for required_doc_text in (
        'deterministic_entry_clock_v1', '0.19.0, build 26',
        'QueryPerformanceFrequency', 'QueryPerformanceCounter',
        'GetTickCount', 'GetCurrentProcess', 'sixteen synthetic corruptions'):
    assert required_doc_text in startup_doc
assert client.api('/repos/lyszq/NFSU2Recomp/git/ref/heads/main')['object']['sha'] == 'e38069b79c096bd86ea55e4e8e50dec73bb093fa'
for name in ('private-evidence.txt', 'private-linux-evidence.txt'):
    evidence = (a.delivery / name).read_text()
    assert 'FAIL |' not in evidence and 'DIFF |' not in evidence
    assert evidence.count('VERIFIED ENTRY STOP') == 2
    assert evidence.count('cursor fixture (320,180)') == 2
    assert evidence.count('virtual TSC + clock fixtures') == 2
    assert '192955 instructions / 10541 dispatch calls / 1201 registered functions' in evidence
    assert '884 implemented API calls' in evidence
    assert 'x86 trace + GPR/EFLAGS + image/TEB/stack/heap/process match' in evidence
    if name == 'private-evidence.txt':
        assert a.source in evidence and 'Native probe host: Darwin ' in evidence
        for symbol in ('sub_0048b1e0', 'sub_0075bcc7', 'nfs_private_startup_probe', 'guest_execution_run', 'guest_execution_rdtsc', 'guest_clock_import', 'guest_heap_realloc', 'guest_registry_import', 'guest_cpuid', 'guest_resources_import', 'guest_user_objects_import', 'guest_user_objects_lookup', 'guest_user32_get_cursor_pos', 'guest_cursor_get_snapshot', 'guest_user32_get_system_metrics', 'nfsu2_input_get_cursor_snapshot'):
            assert re.search(r'\s_' + symbol + r'\s*$', evidence, re.M)
    else:
        assert 'Native probe host: Linux x86_64' in evidence

ipa = a.delivery / 'NFSU2iOS-private-unsigned.ipa'
segments = []
with zipfile.ZipFile(ipa) as z:
    for name in z.namelist():
        assert Path(name).suffix.lower() not in ('.exe', '.c', '.h', '.py', '.bin')
        assert 'unicorn' not in name.lower() and '_CodeSignature' not in name and 'embedded.mobileprovision' not in name
    info = plistlib.loads(z.read('Payload/NFSU2iOS.app/Info.plist'))
    assert info['CFBundleIdentifier'] == 'dev.lyszq.nfsu2ios'
    assert info['CFBundleShortVersionString'] == '0.19.0' and info['CFBundleVersion'] == '26'
    binary = z.read('Payload/NFSU2iOS.app/NFSU2iOS')
    magic, cpu, _, filetype, ncmds, _, _, _ = struct.unpack_from('<8I', binary)
    assert magic == 0xfeedfacf and cpu == 0x0100000c and filetype == 2
    offset = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', binary, offset)
        assert size >= 8 and offset + size <= len(binary)
        assert cmd != 0x1d
        if cmd == 0x19:
            label, _, _, _, _, maxprot, initprot = struct.unpack_from('<16sQQQQii', binary, offset + 8)
            assert initprot & 6 != 6 and maxprot & 6 != 6
            segments.append({'name': label.rstrip(b'\0').decode(), 'initial_protection': initprot})
        offset += size

tracked = subprocess.check_output(['git', 'ls-files', '--', 'gen/*', 'out/*', '*.exe', '*.EXE', '*.ipa'], cwd=ROOT, text=True)
assert not tracked
report = dict(version='0.19.0', build='26', source_commit=a.source,
              private_workflow=private['html_url'], public_workflow=public['html_url'],
              private_control_commit=private['head_sha'], private_jobs=[{k: j[k] for k in ('id','name','conclusion')} for j in jobs],
              ipa_bytes=ipa.stat().st_size, ipa_sha256=hashlib.sha256(ipa.read_bytes()).hexdigest(),
              architecture='ARM64', unsigned=True, bundle_id=info['CFBundleIdentifier'], segments=segments,
              native_hosts=['Linux x86_64', 'Darwin x86_64'], native_runs_per_host=2,
              instructions=reference['instructions'], raw_oracle_callbacks=reference['raw_instructions'],
              virtual_tsc_profile=reference['virtual_tsc_profile'],
              virtual_tsc_initial=reference['virtual_tsc_initial'],
              virtual_tsc_increment=reference['virtual_tsc_increment'],
              virtual_tsc_next=reference['virtual_tsc_next'],
              virtual_tsc_reads=len(reference['rdtsc_calls']),
              virtual_tsc_hash=reference['virtual_tsc_hash'],
              rdtsc_events=reference['rdtsc_calls'],
              virtual_tsc_gameplay_time_claim=False,
              clock_profile=reference['clock_profile'], clock=reference['clock'],
              toolhelp_snapshots=reference['toolhelp_snapshots'], unique_observed_targets=len(observed_targets),
              eflags_compare_mask=0x00200cd5,
              eflags_masked=reference['cpu']['eflags_masked'],
              cpuid_profile=reference['cpuid_profile'],
              cpuid_leaves=[x['leaf'] for x in reference['cpuid_calls']],
              cpuid_calls=reference['cpuid_calls'],
              calls=reference['calls'], maximum_depth=reference['maximum_depth'], api_invocations=reference['api_call_count'],
              critical_sections=reference['critical_section_count'], tls_slots=reference['tls_slot_count'],
              tls_threads=reference['tls_thread_count'],
              registered_functions=manifest['startup']['generated_functions'], stop=reference['import_library']+'!'+reference['import_name'],
              exact_trace_and_all_memory_hashes=True, cursor_profile=reference['cursor_profile'], cursor_fixture=reference['cursor_fixture'], user_objects=reference['user_objects'], resource_missing_application_icon=reference['resource_missing_application_icon'], raw_exe_generated_source_reference_engine_bundled=False,
              windows_nls_fixture_sha256=hashlib.sha256((ROOT/'tests/fixtures/windows_nls_cp1252.json').read_bytes()).hexdigest(),
              artifacts=[{k:x.get(k) for k in ('id','name','size_in_bytes','digest')} for x in client.api(f'/repos/{client.repository}/actions/runs/{a.run}/artifacts')['artifacts']],
              physical_device_test='pending', previous_confirmed_device_version='0.17.0',
              previous_confirmed_device='iPad / iPadOS 26.3 / 16 KiB pages',
              live_input_device_test='latest confirmed v0.17; v0.19 pending', game_boot=False, gameplay=False,
              public_main=client.api('/repos/lyszq/NFSU2Recomp/git/ref/heads/main')['object']['sha'],
              working_tree_clean=not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip())
(a.delivery / 'BUILD-VERIFICATION.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
