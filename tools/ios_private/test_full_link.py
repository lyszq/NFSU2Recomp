import unittest
from verify_full_link import REQUIRED, verify

class FullLinkTests(unittest.TestCase):
    def fixture(self):
        objects = [f'/obj/shard_{i:04d}.o' for i in range(128)]
        for name in REQUIRED.values():
            if name and '/obj/' + name not in objects:
                objects.append('/obj/' + name)
        symbols, nm = [], []
        for index, (name, owner) in enumerate(REQUIRED.items()):
            object_index = objects.index('/obj/' + owner) if owner else 0
            symbols.append(f'0x{index + 4096:08X} 0x00000010 [ {object_index}] _{name}')
            nm.append(f'{index + 4096:016x} (__TEXT,__text) external _{name}')
        map_text = '\n'.join(f'[ {i}] {path}' for i, path in enumerate(objects)) + '\n' + '\n'.join(symbols)
        return map_text, '\n'.join(nm)

    def test_complete_strong_link(self):
        map_text, nm = self.fixture()
        self.assertEqual(verify(map_text, nm)['shard_object_count'], 128)

    def test_missing_shard(self):
        map_text, nm = self.fixture()
        with self.assertRaisesRegex(ValueError, '128 shard'):
            verify(map_text.replace('shard_0127.o', 'other.o'), nm)

    def test_distinct_symbol_with_matching_suffix_is_not_a_duplicate(self):
        map_text, nm = self.fixture()
        # The actual iOS app contains both legacy and checked dispatchers.
        result = verify(map_text, nm + '\n000000010002b5ec (__TEXT,__text) non-external (was a private external) _guest_dispatch_init')
        self.assertIn('dispatch_init', result['strong_symbols'])

    def test_weak_backend_is_rejected(self):
        map_text, nm = self.fixture()
        with self.assertRaisesRegex(ValueError, 'weak'):
            verify(map_text, nm.replace('external _metal_available', 'weak external _metal_available'))

    def test_wrong_backend_owner_is_rejected(self):
        map_text, nm = self.fixture()
        with self.assertRaisesRegex(ValueError, 'wrong owner'):
            verify(map_text.replace('/obj/metal.o', '/obj/NFSU2MetalBridge.o'), nm)

    def test_dead_stripped_entry_is_rejected(self):
        map_text, nm = self.fixture()
        with self.assertRaisesRegex(ValueError, 'missing live'):
            verify(map_text.replace(' _sub_0075bcc7', ' _not_entry'), nm)

    def test_unresolved_guest_symbol_is_rejected(self):
        map_text, nm = self.fixture()
        with self.assertRaisesRegex(ValueError, 'unresolved runtime'):
            verify(map_text, nm + '\n                 (undefined) external _sub_00401000')

    def test_system_dispatch_import_is_allowed(self):
        map_text, nm = self.fixture()
        result = verify(map_text, nm + '\n                 (undefined) external _dispatch_async (from libSystem)')
        self.assertEqual(result['dynamic_undefined_count'], 1)

if __name__ == '__main__':
    unittest.main()
