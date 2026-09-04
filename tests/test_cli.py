"""Exercise ``python -m mmkv_parser dump`` end to end, as a subprocess.

The store fixtures are hand-built to the on-disk layout, the same way
test_mmkv_parser.py builds its own, so this file carries no sample data.
"""
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

    def test_encrypted_store_is_refused_with_the_readers_error(self):
        meta = bytearray(32)
        meta[12:28] = bytes(range(1, 17))
        path = self._write(_store(_entry('a', _string_value('b'))), crc=bytes(meta))
        result = self._run('dump', path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('AES-encrypted', result.stderr)

    def test_missing_file_is_an_error_not_a_traceback(self):
        result = self._run('dump', str(REPO_ROOT / 'tests' / 'does-not-exist.mmkv'))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('Traceback', result.stderr)

    def test_dump_needs_a_store_argument(self):
        result = self._run('dump')
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
