#!/usr/bin/env python3
"""Add UI tests to an already authenticated full-runtime overlay, never a probe."""
import argparse
from pathlib import Path
import yaml

def configure(source: Path, destination: Path):
    spec = yaml.safe_load(source.read_text(encoding='utf-8'))
    app = spec['targets']['NFSU2iOS']
    definitions = app['settings']['base'].get('GCC_PREPROCESSOR_DEFINITIONS', [])
    if 'NFS_FULL_RUNTIME=1' not in definitions or 'NFS_ALL_SHARDS=1' not in definitions:
        raise ValueError('simulator smoke requires the authenticated full-runtime overlay')
    if not app['info']['properties'].get('NFSRuntimeSourceSHA'):
        raise ValueError('exact compiled runtime source pin required')
    spec['targets']['FullRuntimeUITests'] = {
        'type': 'bundle.ui-testing', 'platform': 'iOS', 'deploymentTarget': '16.0',
        'sources': [{'path': 'FullRuntimeUITests'}],
        'dependencies': [{'target': 'NFSU2iOS'}],
        'settings': {'base': {'PRODUCT_BUNDLE_IDENTIFIER': 'dev.lyszq.nfsu2ios.fullruntime-uitests',
                              'TEST_TARGET_NAME': 'NFSU2iOS',
                              'GENERATE_INFOPLIST_FILE': 'YES',
                              'CODE_SIGNING_ALLOWED': 'NO'}},
    }
    spec.setdefault('schemes', {})['FullRuntimeSmoke'] = {
        'build': {'targets': {'NFSU2iOS': 'all', 'FullRuntimeUITests': ['test']}},
        'test': {'config': 'Release', 'targets': [{'name': 'FullRuntimeUITests', 'parallelizable': False}],
                 'gatherCoverageData': False},
    }
    destination.write_text(yaml.safe_dump(spec, sort_keys=False), encoding='utf-8')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', type=Path, default=Path('ios/project-private.yml'))
    p.add_argument('--out', type=Path, default=Path('ios/project-full-simulator.yml'))
    a = p.parse_args()
    configure(a.input, a.out)
    print('Configured full-runtime UI test overlay; no simulator test hooks added to app')

if __name__ == '__main__':
    main()
