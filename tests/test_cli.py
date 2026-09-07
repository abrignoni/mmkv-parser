"""Exercise ``python -m mmkv_parser dump`` end to end, as a subprocess.

The store fixtures are hand-built to the on-disk layout, the same way
test_mmkv_parser.py builds its own, so this file carries no sample data.
"""
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


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


def _store(*entries):
    data = b''.join(entries)
    region = _varint(len(data)) + data
    return struct.pack('<I', len(region)) + region + b'\x00' * 64


class DumpCommandTest(unittest.TestCase):

    def _write(self, payload, crc=None):
        handle = tempfile.NamedTemporaryFile(suffix='.mmkv', delete=False)
        handle.write(payload)
        handle.close()
        self.addCleanup(lambda: pathlib.Path(handle.name).unlink(missing_ok=True))
        if crc is not None:
            meta = handle.name + '.crc'
            pathlib.Path(meta).write_bytes(crc)
            self.addCleanup(lambda: pathlib.Path(meta).unlink(missing_ok=True))
        return handle.name

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, '-m', 'mmkv_parser', *args],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)

    def _history_store(self):
        return self._write(_store(
            _entry('channel', _string_value('googleplay')),
            _entry('count', _varint(3)),
            _entry('token', _string_value('first')),
            _entry('token', _string_value('second')),
            _entry('count', b''),
        ))

    def test_dump_prints_every_write_in_file_order(self):
        result = self._run('dump', self._history_store())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "0\t'channel'\t'googleplay'",
            "1\t'count'\t3",
            "2\t'token'\t'first'",
            "3\t'token'\t'second'",
            "4\t'count'\t<removed>",
        ])
        self.assertEqual(result.stderr, '')

    def test_live_keeps_the_last_write_and_drops_removed_keys(self):
        result = self._run('dump', '--live', self._history_store())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "0\t'channel'\t'googleplay'",
            "3\t'token'\t'second'",
        ])

    def test_key_set_again_after_removal_is_live(self):
        path = self._write(_store(
            _entry('flag', _varint(1)),
            _entry('flag', b''),
            _entry('flag', _varint(7)),
        ))
        result = self._run('dump', '--live', path)
        self.assertEqual(result.stdout.splitlines(), ["2\t'flag'\t7"])

    def test_unreadable_store_with_a_vector_is_refused_with_the_readers_error(self):
        region = bytes(range(120, 256)) * 3
        meta = bytearray(32)
        meta[12:28] = bytes(range(1, 17))
        struct.pack_into('<I', meta, 4, 4)
        struct.pack_into('<I', meta, 28, len(region))
        path = self._write(struct.pack('<I', len(region)) + region, crc=bytes(meta))
        result = self._run('dump', path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('encrypted or damaged', result.stderr)

    def test_a_cleared_plaintext_store_is_dumped_not_refused(self):
        payload = _store(_entry('a', _string_value('b')))
        meta = bytearray(32)
        meta[12:28] = bytes(range(1, 17))
        struct.pack_into('<I', meta, 4, 4)
        struct.pack_into('<I', meta, 28, struct.unpack_from('<I', payload, 0)[0])
        result = self._run('dump', self._write(payload, crc=bytes(meta)))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), ["0\t'a'\t'b'"])

    def test_missing_file_is_an_error_not_a_traceback(self):
        result = self._run('dump', str(REPO_ROOT / 'tests' / 'does-not-exist.mmkv'))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('Traceback', result.stderr)

    def _encrypted(self):
        """An encrypted store built with a backend, or None when none is installed."""
        try:
            from Crypto.Cipher import AES  # pylint: disable=import-outside-toplevel
        except ImportError:
            return None, None
        from mmkv_parser import _key_material  # pylint: disable=import-outside-toplevel
        region = _varint(len(_entry('a', _string_value('b')))) + _entry('a', _string_value('b'))
        vector = b'\x02' * 16
        cipher = AES.new(_key_material(b'secret'), AES.MODE_CFB, vector,
                         segment_size=128).encrypt(region)
        meta = bytearray(32)
        struct.pack_into('<I', meta, 4, 4)
        meta[12:28] = vector
        struct.pack_into('<I', meta, 28, len(cipher))
        return self._write(struct.pack('<I', len(cipher)) + cipher + b'\x00' * 32,
                           crc=bytes(meta)), b'secret'

    def test_a_key_reads_an_encrypted_store_and_is_never_printed(self):
        path, key = self._encrypted()
        if path is None:
            self.skipTest('no crypto backend installed')
        result = self._run('dump', '--key', key.decode(), path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["0\t'a'\t'b'"])
        self.assertNotIn('secret', result.stdout + result.stderr)

    def test_a_hex_key_reads_the_same_store(self):
        path, key = self._encrypted()
        if path is None:
            self.skipTest('no crypto backend installed')
        result = self._run('dump', '--key-hex', key.hex(), path)
        self.assertEqual(result.stdout.splitlines(), ["0\t'a'\t'b'"])

    def test_a_wrong_key_exits_with_a_message_and_no_rows(self):
        path, _ = self._encrypted()
        if path is None:
            self.skipTest('no crypto backend installed')
        result = self._run('dump', '--key', 'wrong', path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('did not decrypt', result.stderr)

    def test_malformed_hex_is_rejected_before_anything_is_read(self):
        result = self._run('dump', '--key-hex', 'zz', self._write(_store(_entry('a', b''))))
        self.assertEqual(result.returncode, 2)
        self.assertIn('not valid hex', result.stderr)

    def test_the_two_key_options_are_mutually_exclusive(self):
        result = self._run('dump', '--key', 'a', '--key-hex', '00', 'x')
        self.assertEqual(result.returncode, 2)

    def test_a_size_disagreement_is_noted_on_stderr_without_touching_the_rows(self):
        """The header says one thing and the .crc file another; the rows come from the .crc."""
        region = _varint(len(_entry('k', _string_value('v')))) + _entry('k', _string_value('v'))
        meta = bytearray(32)
        struct.pack_into('<I', meta, 4, 4)
        struct.pack_into('<I', meta, 28, len(region))
        path = self._write(struct.pack('<I', 0) + region + b'\x00' * 32, crc=bytes(meta))
        result = self._run('dump', path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["0\t'k'\t'v'"])
        self.assertIn('the .crc file records', result.stderr)

    def test_no_note_when_the_two_sizes_agree(self):
        result = self._run('dump', self._write(_store(_entry('a', _string_value('b')))))
        self.assertEqual(result.stderr, '')

    def test_dump_needs_a_store_argument(self):
        result = self._run('dump')
        self.assertEqual(result.returncode, 2)

    def test_tabs_and_newlines_in_keys_and_values_stay_on_one_line(self):
        """Keys and strings print as literals, so the only raw tabs are the separators."""
        path = self._write(_store(
            _entry('note', _string_value('first\tsecond\nthird')),
            _entry('odd\tkey', _string_value('x')),
            _entry('blob', b'\x01\t\n\x00raw'),
        ))
        result = self._run('dump', path)
        lines = result.stdout.splitlines()
        self.assertEqual(lines, [
            "0\t'note'\t'first\\tsecond\\nthird'",
            "1\t'odd\\tkey'\t'x'",
            "2\t'blob'\tb'\\x01\\t\\n\\x00raw'",
        ])
        self.assertTrue(all(line.count('\t') == 2 for line in lines))

    def test_pipe_closed_before_anything_is_written_exits_quietly(self):
        """Small output sits in the buffer until exit; the flush must not traceback."""
        path = self._write(_store(_entry('k', _string_value('v'))))
        read_end, write_end = os.pipe()
        os.close(read_end)                        # nobody will ever read
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'mmkv_parser', 'dump', path],
                cwd=str(REPO_ROOT), stdout=write_end, stderr=subprocess.PIPE,
                text=True, check=False)
        finally:
            os.close(write_end)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')

    def test_recover_prints_a_reset_store_and_the_default_prints_nothing(self):
        """A cleared store dumps empty by default and yields its records with --recover."""
        payload = bytearray(_store(
            _entry('channel', _string_value('googleplay')),
            _entry('count', _varint(7)),
        ))
        struct.pack_into('<I', payload, 0, 0)
        path = self._write(bytes(payload))

        plain = self._run('dump', path)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertEqual(plain.stdout, '')

        recovered = self._run('dump', '--recover', path)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(recovered.stdout.splitlines(),
                         ["0\t'channel'\t'googleplay'", "1\t'count'\t7"])

    def test_closed_pipe_is_not_reported_as_a_store_error(self):
        """`dump big-store | head -1` must exit quietly: no message, no traceback."""
        path = self._write(_store(*(
            _entry(f'key{index:05d}', _string_value('v' * 40)) for index in range(3000))))
        result = subprocess.run(
            f'"{sys.executable}" -m mmkv_parser dump "{path}" | head -1',
            shell=True, cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(result.stdout.splitlines(), ["0\t'key00000'\t'" + 'v' * 40 + "'"])


if __name__ == '__main__':
    unittest.main()
