import tempfile
import unittest
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch
import yaml
from configure_simulator import configure
import simulator_smoke
from simulator_smoke import boot_and_install, select_device, supported_host_architecture
from verify_simulator_smoke import inspect

class SimulatorEvidenceTests(unittest.TestCase):
    def fixture(self):
        return 'runtime_source_sha=' + 'a'*40 + '\nruntime guest entry begin: eip=0x0075bcc7\n'

    def test_actual_entry_evidence_keeps_gameplay_and_device_unverified(self):
        report = inspect(self.fixture(), 'a'*40)
        self.assertTrue(report['actual_entry_invocation_observed'])
        for name in ['game_boot', 'real_game_frame', 'gameplay_audio', 'playable_race']:
            self.assertFalse(report[name])
        self.assertEqual(report['arm64_device_validation'], 'not performed')

    def test_other_compiled_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'source pin'):
            inspect(self.fixture(), 'b'*40)

    def test_source_prefix_collision_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'source pin'):
            inspect(self.fixture().replace('a'*40, 'a'*41), 'a'*40)

    def test_initialized_without_actual_entry_marker_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'actual guest entry'):
            inspect('runtime_source_sha=' + 'a'*40, 'a'*40)

    def test_only_available_ios_ipad_is_selected(self):
        device = {'name':'iPad Pro (13-inch)', 'isAvailable':True, 'udid':'12345678-1234-1234-1234-123456789abc'}
        unavailable = dict(device, name='iPad unavailable', isAvailable=False)
        inventory = {'devices': {'com.apple.CoreSimulator.SimRuntime.iOS-18-5':[device, unavailable],
                                 'com.apple.CoreSimulator.SimRuntime.tvOS-18-5':[dict(device)]}}
        self.assertEqual(select_device(inventory)['name'], device['name'])

    def test_missing_simulator_is_an_explicit_environment_failure(self):
        with self.assertRaisesRegex(ValueError, 'no available iPad'):
            select_device({'devices': {}})

    def test_future_runtime_is_not_selected_for_the_active_xcode_sdk(self):
        device = {'name':'iPad Pro', 'isAvailable':True, 'udid':'12345678-1234-1234-1234-123456789abc'}
        inventory = {'devices': {'com.apple.CoreSimulator.SimRuntime.iOS-18-5':[device],
                                 'com.apple.CoreSimulator.SimRuntime.iOS-26-2':[dict(device)]}}
        self.assertEqual(select_device(inventory, '18.5')['runtime'], 'com.apple.CoreSimulator.SimRuntime.iOS-18-5')

    def test_only_future_runtime_is_an_environment_failure(self):
        device = {'name':'iPad Pro', 'isAvailable':True, 'udid':'12345678-1234-1234-1234-123456789abc'}
        with self.assertRaisesRegex(ValueError, 'matching active SDK'):
            select_device({'devices': {'com.apple.CoreSimulator.SimRuntime.iOS-26-2':[device]}}, '18.5')

    def test_select_command_records_device_and_sdk_without_booting(self):
        device = {'name':'iPad Pro', 'isAvailable':True, 'udid':'12345678-1234-1234-1234-123456789abc'}
        inventory = {'devices': {'com.apple.CoreSimulator.SimRuntime.iOS-18-5':[device]}}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'simulator.json'
            with patch.object(simulator_smoke, 'capture',
                              side_effect=[json.dumps(inventory), '18.5', 'x86_64']), \
                 patch.object(simulator_smoke.subprocess, 'run') as run, \
                 patch.object(sys, 'argv', ['simulator_smoke.py', 'select', '--out', str(output)]), \
                 patch.dict(os.environ, {}, clear=True):
                simulator_smoke.main()
            run.assert_not_called()
            selected = json.loads(output.read_text())
            self.assertEqual(selected['runtime'], 'com.apple.CoreSimulator.SimRuntime.iOS-18-5')
            self.assertEqual(selected['sdk_version'], '18.5')
            self.assertEqual(selected['host_arch'], 'x86_64')

    def test_run_phase_waits_for_boot_before_install(self):
        calls = []
        app = Path('/private/NFSU2iOS.app')
        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
        boot_and_install('sim-udid', app, runner=fake_run)
        self.assertEqual([call[0][2] for call in calls],
                         ['boot', 'bootstatus', 'terminate', 'install'])
        self.assertEqual(calls[1][0], ['xcrun', 'simctl', 'bootstatus', 'sim-udid', '-b'])
        self.assertEqual(calls[-1][0],
                         ['xcrun', 'simctl', 'install', 'sim-udid', str(app)])

    def test_simulator_build_architecture_is_limited_to_supported_hosts(self):
        self.assertEqual(supported_host_architecture('x86_64'), 'x86_64')
        self.assertEqual(supported_host_architecture('arm64'), 'arm64')
        with self.assertRaisesRegex(ValueError, 'unsupported iOS Simulator host architecture'):
            supported_host_architecture('i386')

    def test_bounded_overlay_is_rejected_before_adding_ui_test_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = {'targets': {'NFSU2iOS': {'settings': {'base': {}}, 'info': {'properties': {}}}}}
            (root/'in.yml').write_text(yaml.safe_dump(spec))
            with self.assertRaisesRegex(ValueError, 'full-runtime overlay'):
                configure(root/'in.yml', root/'out.yml')

    def test_ui_tests_preserve_the_production_full_runtime_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = {'settings': {'base': {'GCC_PREPROCESSOR_DEFINITIONS': ['NFS_FULL_RUNTIME=1','NFS_ALL_SHARDS=1']}},
                   'sources': [{'path':'../gen/all/shard_0000.c'}],
                   'info': {'properties': {'NFSRuntimeSourceSHA':'a'*40}}}
            (root/'in.yml').write_text(yaml.safe_dump({'targets': {'NFSU2iOS': app}}))
            configure(root/'in.yml', root/'out.yml')
            output = yaml.safe_load((root/'out.yml').read_text())
            self.assertEqual(output['targets']['NFSU2iOS'], app)
            self.assertEqual(output['targets']['FullRuntimeUITests']['type'], 'bundle.ui-testing')

if __name__ == '__main__':
    unittest.main()
