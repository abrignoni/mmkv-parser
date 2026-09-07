"""Pin decryption and the choice of which recorded size bounds the read.

Two properties are checked here that the plain reader tests cannot reach.

**The cipher.** MMKV encrypts with AES-CFB using 128-bit segments. The published
CFB128-AES128 vector from NIST SP 800-38A F.3.13 is asserted first, as a literal,
so the backend is shown to implement the mode MMKV uses before anything is built
on top of it. Where two backends are installed the encrypted fixture is built with
the one the reader will not use, so the fixture is not produced by the code under
test.

**The size.** From meta version 3 the .crc file carries its own copy of the data
region length, and that is the one MMKV reads. Below that version only the header
has it. A meta size that does not fit inside the file is not usable and the header
is read instead.

Every buffer here is built by hand, so this file carries no sample data.
"""
import binascii
import importlib
import pathlib
import struct
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mmkv_parser import (  # pylint: disable=wrong-import-position
    MMKVError,
    _key_material,
    read_dict,
    read_entries,
)

# NIST SP 800-38A, F.3.13 CFB128-AES128.Encrypt. Written out as literals, never
# derived from the module under test.
NIST_KEY = binascii.unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
NIST_IV = binascii.unhexlify('000102030405060708090a0b0c0d0e0f')
NIST_PLAINTEXT = binascii.unhexlify(
    '6bc1bee22e409f96e93d7e117393172a' + 'ae2d8a571e03ac9c9eb76fac45af8e51'
    + '30c81c46a35ce411e5fbc1191a0a52ef' + 'f69f2445df4f9b17ad2b417be66c3710')
NIST_CIPHERTEXT = binascii.unhexlify(
    '3b3fd92eb72dad20333449f8e83cfb4a' + 'c8a64537a0b3a93fcde3cdad9f1ce58b'
    + '26751f67a3cbb140b1808cf187a4f4df' + 'c04b05357c5d1c0eeac4c66f9ff7f2e6')


def _pycryptodome_encrypt(data, key, iv):
    from Crypto.Cipher import AES  # pylint: disable=import-outside-toplevel
    return AES.new(key, AES.MODE_CFB, iv, segment_size=128).encrypt(data)


def _cryptography_encrypt(data, key, iv):
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB  # pylint: disable=import-outside-toplevel
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB  # pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms  # pylint: disable=import-outside-toplevel
    encryptor = Cipher(algorithms.AES(key), CFB(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _available():
    """Return the encrypt helpers whose backend is importable, in reader order."""
    found = []
    for name, helper in (('Crypto.Cipher', _pycryptodome_encrypt),
                         ('cryptography.hazmat.primitives.ciphers', _cryptography_encrypt)):
        try:
            importlib.import_module(name)
        except ImportError:
            continue
        found.append(helper)
    return found


BACKENDS = _available()


def fixture_encrypt(data, key, iv):
    """Encrypt a fixture with the backend the reader will NOT use, where there are two.

    The reader tries pycryptodome first, so building the fixture with the last
    available backend keeps the bytes under test away from the decrypting code.
    """
    if not BACKENDS:
        raise unittest.SkipTest('no crypto backend installed')
    return BACKENDS[-1](data, key, iv)


def _varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _string_value(text):
    encoded = text.encode('utf-8')
    return _varint(len(encoded)) + encoded


def _entry(key, container):
    encoded_key = key.encode('utf-8')
    return _varint(len(encoded_key)) + encoded_key + _varint(len(container)) + container


def _region(*entries):
    data = b''.join(entries)
    return _varint(len(data)) + data


def _meta(version=0, vector=b'\x00' * 16, actual_size=0, length=32):
    out = bytearray(length)
    struct.pack_into('<I', out, 4, version)
    out[12:28] = vector
    if length >= 32:
        struct.pack_into('<I', out, 28, actual_size)
    return bytes(out)


class CipherTest(unittest.TestCase):
    """The backend must implement CFB with 128-bit segments, not the 8-bit default."""

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_every_backend_matches_the_published_cfb128_vector(self):
        for encrypt in BACKENDS:
            with self.subTest(backend=encrypt.__name__):
                self.assertEqual(encrypt(NIST_PLAINTEXT, NIST_KEY, NIST_IV), NIST_CIPHERTEXT)

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_the_reader_decrypts_the_published_vector(self):
        from mmkv_parser import _decrypt  # pylint: disable=import-outside-toplevel
        self.assertEqual(_decrypt(NIST_CIPHERTEXT, NIST_KEY, NIST_IV), NIST_PLAINTEXT)


class KeyMaterialTest(unittest.TestCase):
    """AESCrypt copies min(len(key), 16 or 32) bytes into a zero-filled buffer."""

    def test_short_key_is_zero_padded(self):
        self.assertEqual(_key_material(b'abc'), b'abc' + b'\x00' * 13)

    def test_long_key_is_truncated(self):
        self.assertEqual(_key_material(b'x' * 40), b'x' * 16)

    def test_aes256_uses_thirty_two_bytes(self):
        self.assertEqual(_key_material(b'abc', aes256=True), b'abc' + b'\x00' * 29)
        self.assertEqual(_key_material(b'x' * 40, aes256=True), b'x' * 32)

    def test_a_string_key_is_taken_as_utf8(self):
        self.assertEqual(_key_material('abc'), _key_material(b'abc'))

    def test_an_empty_or_wrongly_typed_key_is_refused(self):
        for bad in (b'', '', 17, None):
            with self.assertRaises(MMKVError):
                _key_material(bad)


class EncryptedStoreTest(unittest.TestCase):

    KEY = b'a-key-for-testing'

    def _write(self, payload, meta=None):
        handle = tempfile.NamedTemporaryFile(suffix='.mmkv', delete=False)
        handle.write(payload)
        handle.close()
        self.addCleanup(lambda: pathlib.Path(handle.name).unlink(missing_ok=True))
        if meta is not None:
            path = handle.name + '.crc'
            pathlib.Path(path).write_bytes(meta)
            self.addCleanup(lambda: pathlib.Path(path).unlink(missing_ok=True))
        return handle.name

    def _encrypted_store(self, key=None, vector=b'\x01' * 16, version=4):
        region = _region(_entry('channel', _string_value('googleplay')),
                         _entry('version', _varint(33)))
        cipher = fixture_encrypt(region, _key_material(key or self.KEY), vector)
        payload = struct.pack('<I', len(cipher)) + cipher + b'\x00' * 64
        return self._write(payload, _meta(version=version, vector=vector,
                                          actual_size=len(cipher)))

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_the_right_key_reads_the_store(self):
        path = self._encrypted_store()
        self.assertEqual(read_dict(path, key=self.KEY),
                         {'channel': 'googleplay', 'version': 33})
        self.assertEqual(len(read_entries(path, key=self.KEY)), 2)

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_no_key_still_refuses_rather_than_returning_garbage(self):
        path = self._encrypted_store()
        with self.assertRaises(MMKVError) as caught:
            read_entries(path)
        self.assertIn('encrypted or damaged', str(caught.exception))

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_ciphertext_never_accounts_for_itself_as_plaintext_records(self):
        """The control behind reading the region instead of the meta file's vector.

        The reader calls a region plaintext when its records account for every byte of
        the recorded size. That is only safe if ciphertext does not do so by accident.
        Fixed keys and vectors, so this is a pinned result and not a sampling.
        """
        region = _region(_entry('channel', _string_value('googleplay')),
                         _entry('version', _varint(33)),
                         _entry('installer', _string_value('com.android.vending')))
        clean = 0
        for seed in range(200):
            key = _key_material(b'k%d' % seed)
            vector = bytes(((seed * 7 + i * 31) % 256) for i in range(16))
            cipher = fixture_encrypt(region, key, vector)
            path = self._write(struct.pack('<I', len(cipher)) + cipher,
                               _meta(version=4, vector=vector, actual_size=len(cipher)))
            try:
                read_entries(path)
                clean += 1
            except MMKVError:
                pass
        self.assertEqual(clean, 0)

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_recover_returns_nothing_for_a_reset_store_that_is_encrypted(self):
        """Ciphertext does not walk, so the content test excludes it with no vector check."""
        region = _region(_entry('channel', _string_value('googleplay')))
        vector = b'\x01' * 16
        cipher = fixture_encrypt(region, _key_material(self.KEY), vector)
        path = self._write(struct.pack('<I', 0) + cipher + b'\x00' * 64,
                           _meta(version=4, vector=vector, actual_size=0))
        self.assertEqual(read_entries(path, recover=True), [])

    def test_a_cleared_plaintext_store_is_not_mistaken_for_ciphertext(self):
        """clearAll writes a vector for plaintext stores too; the region decides."""
        region = _region(_entry('channel', _string_value('googleplay')))
        path = self._write(struct.pack('<I', len(region)) + region,
                           _meta(version=4, vector=b'\x9c' * 16, actual_size=len(region)))
        self.assertEqual(read_dict(path), {'channel': 'googleplay'})
        # and a key handed to it is ignored, as for any store that is not encrypted
        self.assertEqual(read_dict(path, key=self.KEY), {'channel': 'googleplay'})

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_a_wrong_key_is_refused_rather_than_returning_a_partial_read(self):
        path = self._encrypted_store()
        # Each of these differs inside the first sixteen bytes, which is all MMKV keeps.
        for wrong in (b'not-the-key', b'A-key-for-testing', b'\x00' * 16):
            with self.subTest(key=wrong):
                with self.assertRaises(MMKVError) as caught:
                    read_entries(path, key=wrong)
                self.assertIn('did not decrypt', str(caught.exception))

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_two_keys_differing_only_past_the_sixteenth_byte_are_one_key(self):
        """AESCrypt keeps sixteen bytes, so a longer key is cut and the tail is not used.

        An examiner testing candidate keys needs to know this: two passphrases that
        share their first sixteen bytes open the same store, and a key that looks
        wrong past that point is not wrong at all.
        """
        path = self._encrypted_store(key=b'a-key-for-testing')
        self.assertEqual(_key_material(b'a-key-for-testing'), _key_material(b'a-key-for-testinX'))
        self.assertEqual(read_dict(path, key=b'a-key-for-testinX'),
                         {'channel': 'googleplay', 'version': 33})

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_a_key_is_ignored_for_a_store_that_is_not_encrypted(self):
        region = _region(_entry('a', _string_value('b')))
        path = self._write(struct.pack('<I', len(region)) + region + b'\x00' * 16,
                           _meta(version=4, actual_size=len(region)))
        self.assertEqual(read_dict(path, key=b'irrelevant'), {'a': 'b'})

    def test_a_missing_backend_is_an_error_that_names_the_packages(self):
        """Forced even when a backend is installed, so this path is never unexercised."""
        saved = {name: sys.modules.get(name) for name in
                 ('Crypto', 'Crypto.Cipher', 'cryptography',
                  'cryptography.hazmat.primitives.ciphers',
                  'cryptography.hazmat.decrepit.ciphers.modes',
                  'cryptography.hazmat.primitives.ciphers.modes')}
        for name in saved:
            sys.modules[name] = None          # an import of None raises ImportError
        try:
            from mmkv_parser import _decrypt  # pylint: disable=import-outside-toplevel
            with self.assertRaises(MMKVError) as caught:
                _decrypt(b'\x00' * 32, b'k' * 16, b'v' * 16)
            self.assertIn('pycryptodome', str(caught.exception))
            self.assertIn('cryptography', str(caught.exception))
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module


class RegionSizeTest(unittest.TestCase):
    """From meta version 3 the .crc file's size is the record; below it, the header."""

    REGION = _region(_entry('alpha', _string_value('one')),
                     _entry('beta', _string_value('two')))
    BOTH = {'alpha': 'one', 'beta': 'two'}

    def _store(self, header_size, meta, region=None):
        payload = struct.pack('<I', header_size) + (self.REGION if region is None else region) + b'\x00' * 64
        handle = tempfile.NamedTemporaryFile(suffix='.mmkv', delete=False)
        handle.write(payload)
        handle.close()
        self.addCleanup(lambda: pathlib.Path(handle.name).unlink(missing_ok=True))
        if meta is not None:
            path = handle.name + '.crc'
            pathlib.Path(path).write_bytes(meta)
            self.addCleanup(lambda: pathlib.Path(path).unlink(missing_ok=True))
        return handle.name

    def test_meta_size_wins_over_a_header_that_was_left_behind(self):
        """A 2.4.0 store: the header stopped being maintained, the meta file carries it."""
        path = self._store(header_size=0,
                           meta=_meta(version=4, actual_size=len(self.REGION)))
        self.assertEqual(read_dict(path), self.BOTH)

    def test_meta_size_wins_at_version_three(self):
        path = self._store(header_size=0,
                           meta=_meta(version=3, actual_size=len(self.REGION)))
        self.assertEqual(read_dict(path), self.BOTH)

    def test_the_header_stands_below_version_three(self):
        """A version 2 meta has no size field, so its bytes there must be ignored."""
        path = self._store(header_size=0, meta=_meta(version=2, actual_size=len(self.REGION)))
        self.assertEqual(read_entries(path), [])
        path = self._store(header_size=len(self.REGION),
                           meta=_meta(version=2, actual_size=999999))
        self.assertEqual(read_dict(path), self.BOTH)

    def test_a_meta_size_past_the_end_of_the_file_falls_back_to_the_header(self):
        path = self._store(header_size=len(self.REGION),
                           meta=_meta(version=4, actual_size=10 ** 6))
        self.assertEqual(read_dict(path), self.BOTH)

    def test_a_meta_too_short_for_the_size_field_leaves_the_header_in_charge(self):
        """The vector still has to be read from a short meta; only the size is absent."""
        path = self._store(header_size=len(self.REGION), meta=_meta(version=4, length=28))
        self.assertEqual(read_dict(path), self.BOTH)

    @unittest.skipUnless(BACKENDS, 'no crypto backend installed')
    def test_a_short_meta_still_reports_an_encrypted_store(self):
        """The vector is read from a short meta so a real encrypted store is still refused."""
        vector = bytes(range(1, 17))
        cipher = fixture_encrypt(self.REGION, _key_material(b'a-key-for-testing'), vector)
        path = self._store(region=cipher, header_size=len(cipher),
                           meta=_meta(version=2, vector=vector, length=28))
        with self.assertRaises(MMKVError) as caught:
            read_entries(path)
        self.assertIn('encrypted or damaged', str(caught.exception))

    def test_a_short_meta_with_a_vector_does_not_refuse_a_plaintext_store(self):
        path = self._store(header_size=len(self.REGION),
                           meta=_meta(version=2, vector=bytes(range(1, 17)), length=28))
        self.assertEqual(read_dict(path), self.BOTH)

    def test_no_meta_file_at_all_leaves_the_header_in_charge(self):
        path = self._store(header_size=len(self.REGION), meta=None)
        self.assertEqual(read_dict(path), self.BOTH)


if __name__ == '__main__':
    unittest.main()
