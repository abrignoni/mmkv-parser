"""Command line entry point: ``python -m mmkv_parser dump <store>``.

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
refused with the reader's own MMKVError. Nothing here decrypts.
"""
import argparse
import os
import sys

from . import MMKVError, decode_value, read_entries


def _render(value):
    if value is None:
        return '<removed>'
    if isinstance(value, (str, bytes)):
        return repr(value)
    return str(value)


def dump(path, live=False, out=sys.stdout):
    """Print the entries of the store at ``path``; see the module docstring."""
    entries = read_entries(path)
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
    args = parser.parse_args(argv)

    try:
        dump(args.store, live=args.live)
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
