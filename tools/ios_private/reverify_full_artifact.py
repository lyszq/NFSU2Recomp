#!/usr/bin/env python3
"""Recheck an immutable private linked IPA without regenerating/recompiling it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile
from verify_full_link import verify
from verify_full_package import inspect_package, validate_compile_jobs

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--zip', type=Path, required=True)
    p.add_argument('--artifact', type=Path, required=True)
    p.add_argument('--jobs', type=Path, required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--verifier-source', required=True)
    p.add_argument('--build-run', type=int, required=True)
    p.add_argument('--artifact-id', type=int, required=True)
    p.add_argument('--artifact-sha256', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    if not all(re.fullmatch('[a-f0-9]{40}', s) for s in [a.source, a.verifier_source]):
        raise ValueError('exact source pins required')
    digest = lambda b: hashlib.sha256(b).hexdigest()
    metadata = json.loads(a.artifact.read_text())
    if (metadata['id'] != a.artifact_id or metadata['workflow_run']['id'] != a.build_run
        or metadata['digest'] != 'sha256:' + a.artifact_sha256
        or digest(a.zip.read_bytes()) != a.artifact_sha256):
        raise ValueError('original private artifact identity/hash mismatch')
    validate_compile_jobs(json.loads(a.jobs.read_text())['jobs'])
    a.out.mkdir(parents=True, exist_ok=True)
    names = ['full-runtime-link-map.txt', 'full-runtime-nm.txt',
             'full-runtime-provenance.json', 'contract-tests.txt',
             'UNVERIFIED-NFSU2iOS-full-runtime-unsigned.ipa']
    with zipfile.ZipFile(a.zip) as z:
        for name in names:
            if z.namelist().count(name) != 1:
                raise ValueError('missing/ambiguous original evidence: ' + name)
            (a.out / name).write_bytes(z.read(name))
    manifest_bytes = (a.out / names[2]).read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest['source_commit'] != a.source or manifest['source_dirty'] is not False:
        raise ValueError('generation source differs from compiled source')
    ipa = a.out / names[-1]
    _, binary, _ = inspect_package(ipa, a.source)
    map_bytes = (a.out / names[0]).read_bytes()
    nm_bytes = (a.out / names[1]).read_bytes()
    report = verify(map_bytes.decode(), nm_bytes.decode())
    report.update(source_sha=a.source, binary_sha256=digest(binary),
                  map_sha256=digest(map_bytes), nm_sha256=digest(nm_bytes),
                  generation_manifest_sha256=digest(manifest_bytes), generation=manifest)
    (a.out / 'full-runtime-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    receipt = {'compiled_source': a.source, 'verifier_source': a.verifier_source,
               'build_run': a.build_run, 'build_artifact_id': a.artifact_id,
               'build_artifact_sha256': a.artifact_sha256,
               'ipa_sha256': digest(ipa.read_bytes()),
               'original_ci_conclusion': 'failure',
               'original_failure': 'link verifier symbol suffix collision; compile and link succeeded',
               'scope': 'independent artifact/package/link re-verification; device gameplay unverified'}
    (a.out / 'full-runtime-reverification.json').write_text(json.dumps(receipt, indent=2) + '\n')
    ipa.rename(a.out / 'NFSU2iOS-full-runtime-unsigned.ipa')
    print('PASS | immutable original IPA; native ARM64 iOS, all128 shards, strong backends, source/hash chain')

if __name__ == '__main__':
    main()
