import struct
import unittest
from verify_full_package import inspect_binary, validate_compile_jobs

class PackageBinaryTests(unittest.TestCase):
    def fixture(self, protection=5, platform=2, signature=False):
        segment = struct.pack('<II16sQQQQiiII', 0x19, 72, b'__TEXT', 0, 0, 0, 0,
                              protection, protection, 0, 0)
        build = struct.pack('<6I', 0x32, 24, platform, 0x100000, 0x1a0000, 0)
        commands = segment + build + (struct.pack('<II', 0x1d, 8) if signature else b'')
        return struct.pack('<8I', 0xfeedfacf, 0x0100000c, 0, 2, 3 if signature else 2,
                           len(commands), 0, 0) + commands

    def test_native_ios_read_execute_is_accepted(self):
        self.assertEqual(inspect_binary(self.fixture())[0]['initial_protection'], 5)

    def test_write_execute_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'write/execute'):
            inspect_binary(self.fixture(protection=7))

    def test_macos_platform_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'iOS'):
            inspect_binary(self.fixture(platform=1))

    def test_signed_artifact_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'signature'):
            inspect_binary(self.fixture(signature=True))

class ReplayGateTests(unittest.TestCase):
    def fixture(self):
        return [{'name':'native-reference-linux', 'conclusion':'success'},
                {'name':'full-runtime-ios', 'conclusion':'failure', 'steps':[
                    {'name':'Compile and link the complete ARM64 iOS runtime', 'conclusion':'success'},
                    {'name':'Verify all shard objects and strong real backend linkage', 'conclusion':'failure'}]}]

    def test_only_verifier_failure_after_successful_compile_is_accepted(self):
        validate_compile_jobs(self.fixture())

    def test_compile_failure_is_rejected(self):
        jobs = self.fixture()
        jobs[1]['steps'][0]['conclusion'] = 'failure'
        with self.assertRaisesRegex(ValueError, 'successful compile/link'):
            validate_compile_jobs(jobs)

    def test_native_failure_is_rejected(self):
        jobs = self.fixture()
        jobs[0]['conclusion'] = 'failure'
        with self.assertRaisesRegex(ValueError, 'native reference'):
            validate_compile_jobs(jobs)

    def test_additional_failure_is_rejected(self):
        jobs = self.fixture()
        jobs[1]['steps'].append({'name':'Another step', 'conclusion':'failure'})
        with self.assertRaisesRegex(ValueError, 'only a verifier'):
            validate_compile_jobs(jobs)

if __name__ == '__main__':
    unittest.main()
