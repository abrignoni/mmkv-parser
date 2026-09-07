"""Command line entry point: ``python -m mmkv_parser dump <store>``.

``carve <store>`` reads the space past the recorded data region instead. Those
results are inferences and some are wrong; the caveat is printed to stderr on
every run and the reasoning is in ``carve_slack``.

Prints one line per entry in file order, tab separated: the write index (the
entry's position in the file, counting from 0), the key, and the decoded value.
Every entry is printed by default, so a key that was written more than once
appears once per write and the superseded values stay visible. ``--live``
collapses to the last write of each key and drops removed keys, which is the
view the app itself reads.

Keys and string values are printed as Python literals, so an empty string, a
string that looks like a number, and a number stay distinguishable: strings are
quoted, integers are bare, a removal marker prints as ``<removed>``, and a
container that decodes as neither prints as a bytes literal.

An encrypted store (a non-zero AES vector in the sibling ``.crc`` file) is
refused unless a key is supplied with ``--key`` or ``--key-hex``. The key is
never printed and never looked for; a key that does not decrypt the store is
reported as such rather than dumping garbage.

``--recover`` applies to a store whose recorded size is zero, the state MMKV leaves
behind when it clears a store or fails its CRC: the records are still in the file. It
walks the surviving region and prints what it finds, and prints nothing when the region
does not walk cleanly to its zero padding.

When the four-byte header and the ``.crc`` file disagree about the length of the
data region, a note goes to stderr saying which one was read, so a store written
by a release that no longer maintains the header cannot quietly read short.
"""
import argparse
import binascii
import os
import struct
import sys

from . import MMKVError, _read_meta, carve_slack, decode_value, read_entries


def _render(value):
    if value is None:
        return '<removed>'
    if isinstance(value, (str, bytes)):
        return repr(value)
    return str(value)


def size_note(path):
    """Return a note when the header and the .crc file disagree about the region size.

    They agreed on every store measured across 55 extractions, so this is silent in
    practice; it fires on a store whose header was left behind by a release that
    stopped maintaining it.
    """
    meta = _read_meta(path)
    if not meta or meta['actual_size'] is None or meta['version'] < 3:
        return None
    try:
        with open(path, 'rb') as handle:
            header = struct.unpack('<I', handle.read(4))[0]
    except (OSError, struct.error):
        return None
    if header == meta['actual_size']:
        return None
    return (f'note: the header records {header} bytes and the .crc file records '
            f"{meta['actual_size']}; reading the .crc value, which is the one MMKV uses")


def dump(path, live=False, key=None, aes256=False, recover=False, out=sys.stdout):
    """Print the entries of the store at ``path``; see the module docstring."""
    note = size_note(path)
    if note:
        print(note, file=sys.stderr)
    entries = read_entries(path, key=key, aes256=aes256, recover=recover)
    if live:
        latest = {}
        for index, (key, container) in enumerate(entries):
            if decode_value(container) is None:
                latest.pop(key, None)
            else:
                latest[key] = (index, container)
        rows = sorted((index, key, container) for key, (index, container) in latest.items())
    else:
        rows = [(index, key, container) for index, (key, container) in enumerate(entries)]
    for index, key, container in rows:
        print(f'{index}\t{key!r}\t{_render(decode_value(container))}', file=out)


def carve(path, out=sys.stdout):
    """Print the records carved from the space past the recorded region.

    One line per record, tab separated: the record's offset in the file, whether its
    key also exists live in the same store, the key, and the decoded value.
    """
    print('note: carved records are inferences drawn from unallocated space, not parsed '
          'records, and some are wrong; a key marked live-key is corroborated by the '
          'live region, and values holding base64 or hex carve dirty', file=sys.stderr)
    for record in carve_slack(path):
        flag = 'live-key' if record.live_key else '-'
        print(f'{record.offset}\t{flag}\t{record.key!r}\t{_render(decode_value(record.container))}',
              file=out)


def main(argv=None):
    """Parse arguments and run; returns the process exit status."""
    parser = argparse.ArgumentParser(
        prog='python -m mmkv_parser',
        description='Read a Tencent MMKV key-value store file without the app that wrote it.')
    commands = parser.add_subparsers(dest='command', required=True)
    dump_parser = commands.add_parser(
        'dump', help='print every entry of a store in file order, one per line')
    dump_parser.add_argument(
        'store', help='path to the MMKV file; its .crc sibling is read when present')
    dump_parser.add_argument(
        '--live', action='store_true',
        help='print only the last write of each key and drop removed keys')
    key_group = dump_parser.add_mutually_exclusive_group()
    key_group.add_argument(
        '--key', metavar='TEXT',
        help='decrypt with this key, taken as UTF-8 text; nothing is looked for, and '
             'the key is never printed')
    key_group.add_argument(
        '--key-hex', metavar='HEX', dest='key_hex',
        help='decrypt with this key, given as hex, for a key that is not text')
    dump_parser.add_argument(
        '--recover', action='store_true',
        help="print the surviving records of a store whose recorded size is zero, the "
             "state left behind by a clear or a failed CRC; silent for any other store")
    dump_parser.add_argument(
        '--aes256', action='store_true',
        help='the store was created with AES-256; the MMKV default is AES-128')
    carve_parser = commands.add_parser(
        'carve', help='print records recovered from the space past the recorded region')
    carve_parser.add_argument(
        'store', help='path to the MMKV file; its .crc sibling is read when present')
    args = parser.parse_args(argv)

    key = getattr(args, 'key', None)
    if getattr(args, 'key_hex', None):
        try:
            key = binascii.unhexlify(args.key_hex.replace(' ', ''))
        except (binascii.Error, ValueError):
            print('--key-hex is not valid hex', file=sys.stderr)
            return 2

    try:
        if args.command == 'carve':
            carve(args.store)
        else:
            dump(args.store, live=args.live, key=key, aes256=args.aes256,
                 recover=args.recover)
        # Flush here so a closed pipe surfaces inside this handler rather than
        # in the flush Python runs at exit, which cannot be caught.
        sys.stdout.flush()
    except MMKVError as exc:
        print(f'{args.store}: {exc}', file=sys.stderr)
        return 1
    except BrokenPipeError:
        # Whatever was reading stdout closed it (head, grep -m, a pager). Exit
        # quietly, with stdout pointed at the null device so the flush Python
        # runs at exit does not complain about the closed pipe.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except OSError as exc:
        print(f'{args.store}: {exc.strerror or exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
