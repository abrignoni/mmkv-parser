"""Pin what carving the space past the recorded region may and may not claim.

MMKV compacts a store by moving the surviving entries to the front of the region and
lowering the recorded size. Nothing zeroes what the move leaves behind, so earlier
generations of the store stay in the file past the recorded size. A record whose start
survives the move can be read whole; a record the move wrote over loses its key and
length fields and leaves only a fragment of its value, which must not be reported as a
record.

There is no marker to synchronise on, so every offset is tested on its own and anything
record-shaped is returned. That admits false positives, and the tests below fix the two
things that keep the rate down: the key character set, which excludes the space, and the
structural test on the value container.

Buffers are built by hand rather than taken from an extraction, so this test carries no
sample data.
"""
import pathlib
import random
import subprocess
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mmkv_parser import (  # pylint: disable=wrong-import-position
    MMKVError,
    carve_slack,
    read_dict,
)


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


class CarveTest(unittest.TestCase):

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

    def _compacted(self, before, survivors, padding=512):
        """A store rewritten in place: survivors moved to the front, the rest left behind."""
        holder = b'\xff\xff\xff\x07'
        original = holder + b''.join(before)
        payload = bytearray(struct.pack('<I', len(original)) + original + b'\x00' * padding)
        kept = holder + b''.join(survivors)
        payload[4:4 + len(kept)] = kept                     # the memmove
        struct.pack_into('<I', payload, 0, len(kept))       # the lowered recorded size
        return bytes(payload)

    def test_a_record_the_compaction_did_not_reach_is_carved(self):
        alpha = _entry('alpha', _string_value('AAA'))
        gamma = _entry('gamma', _string_value('CCC'))
        path = self._write(self._compacted([alpha, gamma], [alpha]))
        carved = carve_slack(path)
        self.assertEqual([(record.key, record.container) for record in carved],
                         [('gamma', _string_value('CCC'))])
        self.assertFalse(carved[0].live_key)
        self.assertEqual(read_dict(path), {'alpha': 'AAA'})   # the live view is untouched

    def test_a_record_the_compaction_wrote_over_is_not_reported(self):
        """Its key and lengths are gone; only a fragment of the value survives."""
        alpha = _entry('alpha', _string_value('AAA'))
        beta = _entry('betakey', _string_value('SECRET-BETA-VALUE'))
        gamma = _entry('gamma', _string_value('CCC'))
        path = self._write(self._compacted([alpha, beta, gamma], [alpha, gamma]))
        carved = carve_slack(path)
        self.assertNotIn('betakey', [record.key for record in carved])
        self.assertIn(b'BETA-VALUE', pathlib.Path(path).read_bytes())  # the fragment is there

    def test_a_superseded_write_of_a_live_key_is_marked_as_such(self):
        # The padding entry keeps the compaction boundary in front of the old write,
        # so that write survives whole rather than being moved over.
        padding = _entry('padding', _string_value('0123456789012'))
        old = _entry('channel', _string_value('beta'))
        new = _entry('channel', _string_value('googleplay'))
        path = self._write(self._compacted([padding, old, new], [new]))
        carved = [(record.key, record.container, record.live_key) for record in carve_slack(path)]
        self.assertIn(('channel', _string_value('beta'), True), carved)

    def test_a_string_value_can_be_carved_as_though_it_were_a_key(self):
        """The length prefix of a value is a plausible key length, so values masquerade.

        This is the false-positive class the docstring warns about, kept here as a
        worked example so it cannot be mistaken for a defect later. Nothing in the
        bytes distinguishes the two, which is why live_key exists and why carved
        records stay out of read_entries.
        """
        old = _entry('channel', _string_value('beta'))
        new = _entry('channel', _string_value('googleplay'))
        carved = carve_slack(self._write(self._compacted([old, new], [new])))
        self.assertEqual([record.key for record in carved], ['googleplay'])
        self.assertFalse(carved[0].live_key)

    def test_a_removal_marker_and_a_double_are_carved(self):
        keep = _entry('keepme', _string_value('x'))
        removed = _entry('gonekey', b'')
        as_double = _entry('latitude', struct.pack('<d', 41.878113))
        path = self._write(self._compacted([keep, removed, as_double], [keep]))
        carved = {record.key: record.container for record in carve_slack(path)}
        self.assertEqual(carved.get('gonekey'), b'')
        self.assertEqual(carved.get('latitude'), struct.pack('<d', 41.878113))

    def test_the_offset_points_at_the_record_in_the_file(self):
        alpha = _entry('alpha', _string_value('AAA'))
        gamma = _entry('gamma', _string_value('CCC'))
        payload = self._compacted([alpha, gamma], [alpha])
        record = carve_slack(self._write(payload))[0]
        self.assertEqual(payload[record.offset:record.offset + len(gamma)], gamma)

    def test_a_store_with_nothing_past_the_recorded_region_carves_nothing(self):
        holder = b'\xff\xff\xff\x07'
        region = holder + _entry('alpha', _string_value('AAA'))
        self.assertEqual(carve_slack(self._write(struct.pack('<I', len(region)) + region)), [])

    def test_prose_in_the_space_is_not_read_as_records(self):
        """A space is byte 32, so a space-permitting key rule turns text into records."""
        random.seed(11)
        words = ['message', 'user', 'photo', 'session', 'android', 'value', 'and',
                 'profile', 'token', 'update', 'cache', 'request', 'the', 'name']
        prose = (' '.join(random.choice(words) for _ in range(40000))).encode()
        holder = b'\xff\xff\xff\x07'
        region = holder + _entry('alpha', _string_value('AAA'))
        path = self._write(struct.pack('<I', len(region)) + region + prose)

        self.assertEqual(carve_slack(path), [])
        # and the exclusion is what does it: allow the space back and the text carves
        with mock.patch('mmkv_parser._CARVE_KEY', re.compile(r'^[0-9\w \-\$\./]+$')):
            self.assertGreater(len(carve_slack(path)), 100)

    def test_an_encrypted_store_is_refused(self):
        holder = b'\xff\xff\xff\x07'
        region = holder + _entry('alpha', _string_value('AAA'))
        crc = b'\x00' * 12 + b'\x11' * 16 + b'\x00' * 4
        path = self._write(struct.pack('<I', len(region)) + region + b'\x01' * 64, crc=crc)
        with self.assertRaises(MMKVError):
            carve_slack(path)


    def test_the_cli_prints_the_offset_the_flag_and_a_caveat(self):
        alpha = _entry('alpha', _string_value('AAA'))
        gamma = _entry('gamma', _string_value('CCC'))
        path = self._write(self._compacted([alpha, gamma], [alpha]))
        result = subprocess.run(
            [sys.executable, '-m', 'mmkv_parser', 'carve', path],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('inferences', result.stderr)
        fields = result.stdout.strip().split('\t')
        self.assertEqual(fields[1:], ['-', "'gamma'", "'CCC'"])
        self.assertEqual(int(fields[0]), carve_slack(path)[0].offset)


if __name__ == '__main__':
    unittest.main()
