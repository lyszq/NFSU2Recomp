#!/usr/bin/env python3
"""Verify a private full-runtime IPA against exact CI and link provenance."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import zipfile
from provision import GitHub, EXPECTED_SHA
from verify_full_link import verify

ROOT = Path(__file__).resolve().parents[2]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def inspect_binary(binary):
    magic, cpu, _, filetype, count, command_bytes, _, _ = struct.unpack_from('<8I', binary)
    if (magic, cpu, filetype) != (0xfeedfacf, 0x0100000c, 2):
        raise ValueError('expected native ARM64 Mach-O executable')
    offset = 32
    segments = []
    platform = None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', binary, offset)
        if size < 8 or offset + size > len(binary):
            raise ValueError('invalid load-command bounds')
        if cmd == 0x1d:
            raise ValueError('unexpected code signature in unsigned delivery')
        if cmd == 0x19:
            label, _, _, _, _, maxprot, initprot = struct.unpack_from('<16sQQQQii', binary, offset + 8)
            if initprot & 6 == 6 or maxprot & 6 == 6:
                raise ValueError('write/execute segment is forbidden')
            segments.append({'name':label.rstrip(b'\0').decode(), 'initial_protection':initprot, 'maximum_protection':maxprot})
        if cmd == 0x32:
            platform = struct.unpack_from('<I', binary, offset + 8)[0]
        offset += size
    if offset != 32 + command_bytes or platform != 2:
        raise ValueError('expected iOS load commands')
    return segments

def inspect_package(ipa, source):
    with zipfile.ZipFile(ipa) as z:
        for name in z.namelist():
            if Path(name).suffix.lower() in {'.exe','.c','.h','.py','.bin'} or any(x in name.lower() for x in ['unicorn','_codesignature','embedded.mobileprovision']):
                raise ValueError('unexpected confidential source, reference engine or signing payload: '+name)
        info=plistlib.loads(z.read('Payload/NFSU2iOS.app/Info.plist'))
        if info['CFBundleIdentifier'] != 'dev.lyszq.nfsu2ios' or (info['CFBundleShortVersionString'],info['CFBundleVersion']) != ('0.20.0','27'):
            raise ValueError('unexpected app identity/version')
        if info.get('NFSRuntimeSourceSHA') != source:
            raise ValueError('app source pin differs from compiled source')
        binary=z.read('Payload/NFSU2iOS.app/NFSU2iOS')
        return info,binary,inspect_binary(binary)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--delivery',type=Path,required=True)
    p.add_argument('--source',required=True)
    p.add_argument('--run',type=int,required=True)
    p.add_argument('--public-run',type=int,required=True)
    a=p.parse_args()
    client=GitHub('NFSU2Recomp-ios-private'); client.private()
    base='/repos/'+client.repository
    private=client.api(base+'/actions/runs/'+str(a.run))
    public=client.api('/repos/lyszq/NFSU2Recomp/actions/runs/'+str(a.public_run))
    jobs=client.api(base+'/actions/runs/'+str(a.run)+'/jobs')['jobs']
    if private['conclusion']!='success' or public['conclusion']!='success' or public['head_sha']!=a.source or not all(j['conclusion']=='success' for j in jobs):
        raise ValueError('exact public/private CI success is required')
    control=private['head_sha']
    workflow=client.api(base+'/contents/.github/workflows/ios-private.yml?ref='+control)
    content=base64.b64decode(workflow['content']).decode()
    if 'SOURCE_SHA: '+a.source not in content or 'configure_project.py --mode all' not in content:
        raise ValueError('private workflow did not pin the complete runtime source')
    tree=client.api(base+'/git/trees/'+control+'?recursive=1')['tree']
    if sorted(x['path'] for x in tree if x['type']=='blob') != ['.github/workflows/ios-private.yml','README.md']:
        raise ValueError('private control repository contains unexpected payload')
    assets=client.api(base+'/releases/tags/private-input-v1')['assets']
    if len(assets)!=1 or assets[0]['name']!='SPEED2.EXE' or assets[0]['size']!=4788224 or assets[0]['digest']!='sha256:'+EXPECTED_SHA:
        raise ValueError('private input identity differs')
    ipa=a.delivery/'NFSU2iOS-full-runtime-unsigned.ipa'
    info,binary,segments=inspect_package(ipa,a.source)
    report=json.loads((a.delivery/'full-runtime-verification.json').read_text())
    manifest_bytes=(a.delivery/'full-runtime-provenance.json').read_bytes()
    if report['source_sha']!=a.source or report['binary_sha256']!=digest(binary) or report['generation_manifest_sha256']!=digest(manifest_bytes):
        raise ValueError('binary/source/generation digest mismatch')
    if report['generation']!=json.loads(manifest_bytes) or report['generation']['source_commit']!=a.source or report['generation']['source_dirty']:
        raise ValueError('generation provenance mismatch')
    for name,key in [('full-runtime-link-map.txt','map_sha256'),('full-runtime-nm.txt','nm_sha256')]:
        if digest((a.delivery/name).read_bytes())!=report[key]: raise ValueError('link evidence digest mismatch')
    actual=verify((a.delivery/'full-runtime-link-map.txt').read_text(),(a.delivery/'full-runtime-nm.txt').read_text())
    if actual['strong_symbols']!=report['strong_symbols'] or actual['shard_object_count']!=128:
        raise ValueError('independent linkage verification differs')
    main_sha=client.api('/repos/lyszq/NFSU2Recomp/git/ref/heads/main')['object']['sha']
    if main_sha!='e38069b79c096bd86ea55e4e8e50dec73bb093fa': raise ValueError('preserved main changed')
    tracked=subprocess.check_output(['git','ls-files','--','gen/*','out/*','*.exe','*.EXE','*.ipa'],cwd=ROOT,text=True)
    if tracked.strip(): raise ValueError('confidential inputs/outputs tracked in public source')
    result={'source_commit':a.source,'private_control_commit':control,'private_ci':private['html_url'],'public_ci':public['html_url'],'private_jobs':[{k:j[k] for k in ['id','name','conclusion']} for j in jobs],'ipa_sha256':digest(ipa.read_bytes()),'ipa_bytes':ipa.stat().st_size,'binary_sha256':digest(binary),'version':info['CFBundleShortVersionString'],'build':info['CFBundleVersion'],'architecture':'ARM64 iOS','unsigned':True,'segments':segments,'shards':128,'generation_summary':report['generation']['summary'],'strong_backend_objects':actual['strong_symbols'],'public_main':main_sha,'device_validation':'pending','game_boot':False,'real_game_frame':False,'gameplay_audio':False,'playable_race':False}
    (a.delivery/'BUILD-VERIFICATION.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    main()
