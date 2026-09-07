# mmkv-parser

A read-only reader for Tencent MMKV key-value store files, written for digital
forensics work. This repository is the canonical home of the module that
[iLEAPP](https://github.com/abrignoni/iLEAPP) and
[ALEAPP](https://github.com/abrignoni/ALEAPP) vendor as `scripts/mmkv_parser.py`.
Pure Python, no dependencies, Python 3.10 or later.

MMKV is the mmap-backed store that WeChat's team open sourced as
[Tencent/MMKV](https://github.com/Tencent/MMKV) (BSD 3-Clause). Android and iOS
apps use it in place of SharedPreferences and NSUserDefaults, so its files turn
up in extractions, most often under the library's default instance name
`mmkv.default` ([MMKVPredef.h](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKVPredef.h#L177)) with a `.crc` file beside it.

## What it reads

- Every entry in file order, including superseded writes of the same key and
  removal markers. The store is append-only between rewrites, so that history
  is part of the evidence.
- The collapsed view the app itself sees: the last write of each key, with
  removed keys dropped.
- The records of a store whose recorded size is zero, on request. Clearing a
  store, and failing its CRC on load, both write a size of zero into the meta
  file and leave the records in place, so the store reads as empty while its
  contents are still on disk. `recover=True` walks the surviving region.
- Records carved out of the space past the recorded data region, through a
  separate call. A compaction moves the surviving entries to the front and
  lowers the recorded size without zeroing what it leaves behind, so earlier
  generations of the store stay in the file. These are inferences, not parsed
  records; see below.
- The two encodings that can be told apart from the bytes alone. A container
  that is exactly a length prefix followed by that many bytes is how MMKV
  writes a string; anything else is read as a varint scalar, which covers the
  integer and boolean types. A container that fits neither comes back as raw
  bytes.

## What it does not do

- Look for a key. Decryption happens only when you pass one. A store whose data
  region does not read as plaintext records, and whose `.crc` meta file carries an
  AES vector, is refused with `MMKVError` instead of being walked, because walking
  ciphertext returns garbage keys that look like data. A key that does not decrypt
  the store is refused the same way rather than returning a partial garbage read.
  The vector on its own is not the test: `clearAll` writes one for plaintext stores
  too, so a store that reads is read.
- Verify the CRC. The meta file records one over the data region as stored, so
  it validates the file rather than the key; the format section gives the field
  for an examiner who wants to check it.
- Carve. `recover` reads a region that is intact and unaccounted for, and it
  returns nothing unless the walk consumes whole entries and then meets nothing
  but the file's zero padding. It scans no offsets and infers no records, so a
  region holding the leftovers of a rewrite is left alone rather than guessed at.
- Let carved records reach the ordinary reads. `carve_slack` is a separate
  call, `read_entries` and `read_dict` never invoke it, and every carved record
  carries its file offset and whether its key also exists live.
- Type values. MMKV records a value's type in the calling code, not in the
  file. One consequence worth knowing: the empty string, the integer 0 and
  `false` are all the single byte `00`, and `decode_value` returns `''` for it.

## Usage

    pip install git+https://github.com/abrignoni/mmkv-parser

or copy `mmkv_parser/__init__.py` next to your code. It is one file.

    from mmkv_parser import MMKVError, decode_value, read_dict, read_entries

    for key, container in read_entries('mmkv.default'):   # file order, repeats kept
        print(key, decode_value(container))

    read_dict('mmkv.default')    # last write of each key, removed keys omitted

    read_dict('store', key='the key the app uses')   # an encrypted store
    read_dict('store', key=b'\x00...', aes256=True)  # created with AES-256

`read_entries` raises `MMKVError` for a file that is not a readable store, for
an encrypted one with no key, and for a key that does not decrypt it. A key is
ignored for a store that is not encrypted. `decode_value` returns a `str`, an
`int`, `None` for a removal marker, or the raw `bytes` when neither reading
applies. The public API is those four names, and the `key` and `aes256`
arguments are optional, so code written against 1.0 keeps working.

Decryption needs `pycryptodome` or `cryptography` importable. Neither is a
dependency: everything else works with nothing installed, which is what lets the
LEAPP cores carry the reader as a single file.

From the command line:

    python -m mmkv_parser dump path/to/store           # every write, in file order
    python -m mmkv_parser dump --live path/to/store    # last write per key, removed keys dropped
    python -m mmkv_parser dump --key 'the key' store   # an encrypted store
    python -m mmkv_parser dump --key-hex 0011.. store  # a key that is not text

Each line is the write index (the entry's position in the file, counting from
0), the key, and the decoded value, tab separated. Keys and strings are quoted
Python literals, so an empty string, a number, and a string that looks like a
number stay distinguishable; a removal prints as `<removed>`. An encrypted store
exits with status 1 and the reader's own message on stderr. The key is never
printed. When the header and the `.crc` file disagree about the length of the
data region, a note on stderr says which was read.

## The format

Read out of Tencent's source at the commits linked under Sources, and checked
against real stores from a local corpus (counts below). No field here is
inferred from a data pattern alone.

    [0:4]              actual_size, uint32 little-endian: length of the data region
    [4:4+actual_size]  data region
        varint         size of the items that follow, 1 to 4 bytes on disk
        entries laid end to end, each:
            varint     key length
            bytes      key, UTF-8
            varint     value container length
            bytes      value container
    remainder          zero padding out to the mmap page size

**Encoding.** Keys are strings and values are protobuf-encoded byte buffers,
and each key-value pair is serialised into the mapped block
([design wiki, Data Organization](https://github.com/Tencent/MMKV/wiki/design_eng/f008c42c66eaf99c618c91ab5b74396de8f01159)). Every length and every
scalar is a base-128 varint, seven bits per byte with the high bit as the
continuation flag ([CodedOutputData.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/CodedOutputData.cpp#L167-L172); `writeUInt32` is that
varint, [CodedOutputData.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/CodedOutputData.cpp#L79-L80)).

**The leading size.** `oldStyleWriteActualSize` copies the data region's length
into the first four bytes ([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L616-L620)), and `readActualSize`
reads it from there when the meta file's version is below 3 and from the meta
file otherwise ([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L602-L611)). Every release from v1.2.0
through v2.3.0 wrote the leading field on every write
([v2.3.0 MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/381b96926b73f7394d9fd0905d2753bd5205ff59/Core/MMKV_IO.cpp#L529-L530)); v2.4.0 gates that write behind meta
version below 3 ([v2.4.0 MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/23d652c17e8c2023bb50f1c92e862a2304eaa2a2/Core/MMKV_IO.cpp#L574-L575), unchanged at
[master](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L629-L630)). Measured on 54 stores whose meta file is at
version 3 or 4 and records a size, from 26 iOS and Android extractions, the
leading field and the meta file's size agreed on all 54; a later sweep of every
registered extraction put that at 875 of 875, with no disagreement anywhere. A
store written only by v2.4.0 or later could differ, so this reader takes the meta
file's `actualSize` field (offset 28) when the meta version is 3 or higher and
the value fits inside the file, which is the rule `MMKV::readActualSize` follows,
and falls back to the header otherwise. On every store measured to date the two
give the same bytes.

**The items-size varint.** The data region opens with one varint holding the
size of the items that follow. How wide it is on disk depends on which release
wrote the file, which is why the reader reads it instead of assuming a width:

- Up to v1.1.x a full rewrite serialised the whole map through MiniPBCoder and
  wrote the buffer out whole, so the region began with MiniPBCoder's own
  compact size prefix ([v1.1.2 MMKV.cpp](https://github.com/Tencent/MMKV/blob/fbb55e6f40917be14e011e9f6dacb061d46d7f9c/Core/MMKV.cpp#L830),
  [v1.1.2 MMKV.cpp](https://github.com/Tencent/MMKV/blob/fbb55e6f40917be14e011e9f6dacb061d46d7f9c/Core/MMKV.cpp#L865), [v1.1.2 MiniPBCoder.cpp](https://github.com/Tencent/MMKV/blob/fbb55e6f40917be14e011e9f6dacb061d46d7f9c/Core/MiniPBCoder.cpp#L63-L64)).
- v1.2.0 introduced a fixed 4-byte slot, `ItemSizeHolderSize = 4`, filled with
  the constant `ItemSizeHolder = 0x00ffffff`, which is the bytes `ff ff ff 07`
  ([v1.2.0 MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/b9820029c1911721e35cf912744089752713e48f/Core/MMKV_IO.cpp#L294-L295); still so at
  [v1.3.5](https://github.com/Tencent/MMKV/blob/9a210a3612d9dbd1b611609469258acc1a5061e5/Core/MMKV_IO.cpp#L341-L342), written on the append path at
  [v1.3.5 MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/9a210a3612d9dbd1b611609469258acc1a5061e5/Core/MMKV_IO.cpp#L912-L915)).
- v2.0.0 onward keeps the 4-byte slot ([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L424)) but fills
  it with a random value whose varint is exactly four bytes long
  ([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L1054-L1057), [AESCrypt.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/aes/AESCrypt.cpp#L43-L52)). A rewrite
  keeps a shorter width already present in the file
  ([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L1311-L1323)), and a rewrite from prepared data writes the
  4-byte slot and then copies the items after MiniPBCoder's own prefix
  ([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L1382-L1390); the prefix is sized at
  [MiniPBCoder.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MiniPBCoder.cpp#L182) and written at
  [MiniPBCoder.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MiniPBCoder.cpp#L76-L77)).

So on disk the varint is 1 to 4 bytes, and the first key follows it. A reader
that assumes a fixed width starts the first key at the wrong offset and reads
zero entries, silently. The known-answer tests exercise every width.

**Append-only, last write wins.** Setting a key appends a new entry rather than
editing the old one, so a changed key appears more than once and the latest
value is the one at the end; MMKV scans all entries at load and keeps the last
occurrence of each key ([design wiki, Write Optimization](https://github.com/Tencent/MMKV/wiki/design_eng/f008c42c66eaf99c618c91ab5b74396de8f01159)). Space
is allocated in page-size units ([MemoryFile.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MemoryFile.cpp#L189-L190),
[MMKV.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV.cpp#L181)); when appending reaches the end, the store is
rewritten with duplicates removed, doubling the file if that is still not
enough ([design wiki, Space Management](https://github.com/Tencent/MMKV/wiki/design_eng/f008c42c66eaf99c618c91ab5b74396de8f01159),
[MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L1188)). `read_entries` returns the whole history in
file order; `read_dict` collapses it.

**Removal is an empty value.** Removing a key appends an entry with a
zero-length value container ([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L890-L901)). `read_dict` drops those
keys; `read_entries` keeps them visible.

**The meta file.** MMKV keeps its integrity and encryption state in a sibling
file named by appending `.crc` to the store's path
([MMKV_IO.h](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.h#L43), [MMKV.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV.cpp#L1733-L1734)). It is the `MMKVMetaInfo`
struct written to disk by `memcpy` ([MMKVMetaInfo.hpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKVMetaInfo.hpp#L79-L81)), so its
layout is the struct's ([MMKVMetaInfo.hpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKVMetaInfo.hpp#L56-L61)):

    [0:4]    crc, uint32 LE      CRC-32 of the data region (actual_size bytes from offset 4)
    [4:8]    version, uint32 LE  which of the fields below are meaningful
    [8:12]   sequence, uint32 LE full write-back count
    [12:28]  aesVector[16]       the AES initialisation vector. NOT an encryption flag
    [28:32]  actualSize, uint32  the data region length, from version 3

The version enum is at [MMKVMetaInfo.hpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKVMetaInfo.hpp#L31-L44): 1 adds the
sequence, 2 the random IV, 3 the actual size, 4 a flags field. The CRC is
computed over the data region starting after the 4-byte header
([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L1758), using the bundled `crc32/Checksum.h`,
[MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKV_IO.cpp#L37)); the wiki describes it as the check that guards
against file system and OS instability ([design wiki, Data Validity](https://github.com/Tencent/MMKV/wiki/design_eng/f008c42c66eaf99c618c91ab5b74396de8f01159))
and says MMKV discards the store by default when the check fails or the file
length is wrong ([android_advance wiki](https://github.com/Tencent/MMKV/wiki/android_advance/f008c42c66eaf99c618c91ab5b74396de8f01159)). Measured: CRC-32 of the
data region equalled the meta file's digest on 65 of 65 non-empty stores
copied from the corpus, across versions 1 through 4. The reader does not
compute it; the field is documented here so an examiner can.

**Encryption.** MMKV encrypts with AES CFB-128 or CFB-256, chosen over CBC
because the store is append-only ([FAQ wiki](https://github.com/Tencent/MMKV/wiki/FAQ/f008c42c66eaf99c618c91ab5b74396de8f01159)); the IV lives in the
meta file ([MMKVPredef.h](https://github.com/Tencent/MMKV/blob/ad7657ef9d120dbcdd7432d75aa6c59391149b22/Core/MMKVPredef.h#L265) for the length). The key is in
neither file, so it has to be supplied; it is then taken the way `AESCrypt` takes
it, truncated to sixteen bytes for AES-128 or thirty-two for AES-256 and
zero-padded if shorter, which means two keys sharing their first sixteen bytes
are one key.

**The vector at bytes 12 to 28 does not mean the store is encrypted.** Encryption
writes it, and so does `MMKV::clearAll`, which fills it with random bytes for every
store it clears and only then checks whether there is a crypter to reset
([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/c74d8b886abd87132c507ec17865a7fb4feb9679/Core/MMKV_IO.cpp#L1476-L1481)).
Nothing anywhere zeroes the field again, so a plaintext store that has ever been
cleared carries a vector for the rest of its life, and so does one that was
decrypted back to plaintext with `reKey("")`
([MMKV_IO.cpp](https://github.com/Tencent/MMKV/blob/c74d8b886abd87132c507ec17865a7fb4feb9679/Core/MMKV_IO.cpp#L1364-L1375)).
That block is unchanged in every release from v1.2.10 to v2.2.2, checked tag by tag.

So this reader decides by reading the region, not by the field. A region whose
records account for every byte of the recorded size is plaintext and is returned as
such, whatever the vector holds. The field is used for what it is: the IV handed to
the cipher once a key is supplied. Earlier versions of this reader refused any store
with a non-zero vector, which silently refused readable plaintext stores; a WeChat
`_slots_id_2` from a live device was the counterexample that established it.

**How a wrong key is caught.** The CRC in the meta file is computed over the data
region as stored, so it validates the file without saying anything about the key.
A structural check does that instead: across 846 readable stores from 55
extractions, a walk consumed the data region to its last byte every single time,
with nothing left over. So a decryption that leaves a tail unread, or that yields
no entries, did not produce an MMKV store, and the reader raises instead of
returning what it managed to read. A plaintext store keeps the gentler behaviour
of returning what was read before the walk lost alignment.

**A recorded size of zero is not an empty store.** `MMKV::clearAll` truncates the
file to the expected capacity and calls `writeActualSize(0, 0, ...)`; the load
path's "file not valid or empty, discard everything" branch does the same when a
store fails its CRC. Neither zeroes the records, and growth is the only thing that
zero-fills, so what sits past the recorded size is the store's own former content
and never another file's. Such a store reads as empty by default, which is what
the app sees. `recover=True` walks the region and returns the entries only when
they account for the whole of it, ending in the zero padding. Measured on 16 such
stores from one iOS extraction, every one walked to clean padding, recovering 1 to
46 entries each, 126 in total; on the same extraction the default output of all 94
stores was unchanged.
## Carving the space past the recorded region

MMKV compacts a store by moving the surviving entries to the front of the region
with a memmove and lowering the recorded size (`memmoveDictionary` and
`doFullWriteBack` in `MMKV_IO.cpp`). Nothing zeroes what the move leaves behind,
and growth is the only operation that zero-fills (`MemoryFile.cpp`), so the bytes
between the recorded size and the end of the file are earlier generations of this
store and never another file's. Across 1,840 stores from 78 extractions, 290 of
the 1,710 unencrypted ones carried something other than zeros there.

`carve_slack(path)` returns a `CarvedRecord` per hit: the offset in the file, the
key, the raw container, and whether the key also exists in the live region.

**They are inferences and some are wrong.** A compaction overwrites the front of
the space, so the first surviving record rarely begins where the space does and
the records are not contiguous. There is no marker to synchronise on, so every
offset is tested on its own. A record is accepted when its key length is 5 to 64
bytes, the key decodes as UTF-8 and matches `[0-9\w\-\$\./:]+`, and its value
container either begins with a length that accounts for the rest of it, is a bare
varint, or is the 4 or 8 bytes MMKV writes a float and a double as.

Measured against data holding no MMKV structure at all: zero false records per KiB
on zero-filled, random, natural-language and JSON input, and about 1.2 per KiB on
base64 and hex text, which nothing here rules out. A store whose values are encoded
blobs will carve dirty.

The space is excluded from the key character set deliberately, and it is what keeps
text out. A space is byte 0x20, which is 32, so in running text it serves as a
key-length field and the 32 bytes after it read as a key: a space-permitting version
of the same test produced 2,469 false records on a megabyte of prose, every one of
them with a space in its key, while only 25 of 91,462 real keys measured across four
extractions contain one. The 5-to-64 window gives up the 1.4% of real keys shorter
than 5 bytes and the 2.0% longer than 64; widening it was measured and rejected,
because it tripled the false positives on base64.

The signal that separates a real carve from a false one is repetition. A real
carved record repeats a key, because that is what a superseded write is, and its
key overlaps the live set; the false ones are each unique and match nothing live.
`live_key` carries that per record.

Encrypted stores are refused. Their space is ciphertext written under an earlier
vector, and while AES-CFB resynchronises after one block, so a key would recover it
past the first 16 bytes, that is not implemented here.

## Vendoring into the LEAPP cores

iLEAPP and ALEAPP carry `mmkv_parser/__init__.py` as `scripts/mmkv_parser.py`,
byte for byte, under a banner naming this repository, the upstream file and
the commit it was copied at. Each core's `admin/scripts/check_vendored.py`
fetches that file at that commit in CI and fails when anything below the
banner differs, so the copies cannot drift by being edited in place. To change
the reader: change it here, land it, copy the new file over the body of each
core's copy, and update the banner's commit line.

## Tests

    python -m unittest discover -s tests -v

`tests/test_mmkv_parser.py` holds the twelve known-answer tests for the reader
itself, against byte fixtures built by hand to the on-disk layout: every items-size width,
superseded writes, removals, a scalar wider than 32 bits, the recorded size
bounding the walk, a truncated walk, and the encrypted-store refusal. They fail
against a reader that assumes a fixed 8-byte header, which is the control they
were written for. `tests/test_cli.py` runs the command line end to end.

`tests/test_encrypted_and_sizes.py` covers the other two. It asserts the
published CFB128-AES128 vector from NIST SP 800-38A F.3.13 as a literal before
anything is built on it, because pycryptodome's `MODE_CFB` defaults to 8-bit
segments and silently returns something other than what MMKV wrote. Where both
backends are installed the encrypted fixture is built with the one the reader
will not use, so the bytes under test are not produced by the code under test.
CI installs both backends and fails the job if any test reports as skipped, then
runs the reader's own suite again with neither installed to prove it needs
nothing.

Nothing under `tests/` comes from an extraction, and the reader's own test file
ships in each core as its own guard.

## Sources

Tencent's code, pinned to commit `ad7657e` of the master branch (2026-08-21)
unless a release tag is named. Each link is checked against the line it cites.

- Tencent/MMKV, `Core/MMKV_IO.cpp`, `Core/MiniPBCoder.cpp`,
  `Core/CodedOutputData.cpp`, `Core/MMKVMetaInfo.hpp`, `Core/MMKV_IO.h`,
  `Core/MMKV.cpp`, `Core/MMKVPredef.h`, `Core/MemoryFile.cpp`,
  `Core/aes/AESCrypt.cpp`, linked inline above. Older behaviour is cited at
  the v1.1.2 (`fbb55e6`), v1.2.0 (`b982002`), v1.3.5 (`9a210a3`),
  v2.3.0 (`381b969`) and v2.4.0 (`23d652c`) tags.
- Tencent/MMKV wiki at `f008c42`: [design](https://github.com/Tencent/MMKV/wiki/design_eng/f008c42c66eaf99c618c91ab5b74396de8f01159),
  [FAQ](https://github.com/Tencent/MMKV/wiki/FAQ/f008c42c66eaf99c618c91ab5b74396de8f01159), [android_advance](https://github.com/Tencent/MMKV/wiki/android_advance/f008c42c66eaf99c618c91ab5b74396de8f01159).

Other readers, useful as second opinions on the layout. All four read the
leading size as a little-endian uint32; three then read one varint and skip it,
and one skips a fixed four bytes:

- [spak9/mmkv_visualizer](https://github.com/spak9/mmkv_visualizer), Python
  served in a browser app. Reads the size, reads and discards the varint after
  it ([mmkv_parser.py](https://github.com/spak9/mmkv_visualizer/blob/d3b41069203f21c7bbd4840b8f95d8cbc20286eb/frontend/public/mmkv_parser.py#L208-L220)), takes the IV from the `.crc` file
  ([mmkv_parser.py](https://github.com/spak9/mmkv_visualizer/blob/d3b41069203f21c7bbd4840b8f95d8cbc20286eb/frontend/public/mmkv_parser.py#L182)) and can decrypt AES-128-CFB given the key
  ([mmkv_parser.py](https://github.com/spak9/mmkv_visualizer/blob/d3b41069203f21c7bbd4840b8f95d8cbc20286eb/frontend/public/mmkv_parser.py#L222)).
- [jixunmoe/mmkv-parser](https://github.com/jixunmoe/mmkv-parser), Rust. Reads
  the size and skips one varint ([mmkv.rs](https://github.com/jixunmoe/mmkv-parser/blob/127a97c5d13d430077b520c8244c2e0e60060bd8/src/mmkv.rs#L45-L54)).
- [syail/mmkv-parser](https://github.com/syail/mmkv-parser), TypeScript. Skips
  four bytes, then one varint ([index.ts](https://github.com/syail/mmkv-parser/blob/fd2f0561aa5f11ecb067588d8d4ef9f9cf011ee8/src/index.ts#L12-L19)).
- [WXjzcccc/go-mmkv](https://github.com/WXjzcccc/go-mmkv), Go. Reads the meta
  file with its version-gated fields ([metadata.go](https://github.com/WXjzcccc/go-mmkv/blob/632d1639bb16860e5f21567d9df3a07a45c3ed38/metadata.go#L48-L51)), checks the
  leading size against the meta size ([vault.go](https://github.com/WXjzcccc/go-mmkv/blob/632d1639bb16860e5f21567d9df3a07a45c3ed38/vault.go#L71)) and the CRC-32
  ([vault.go](https://github.com/WXjzcccc/go-mmkv/blob/632d1639bb16860e5f21567d9df3a07a45c3ed38/vault.go#L81)), can decrypt CFB, then skips a fixed four bytes of the
  region rather than reading the varint ([vault.go](https://github.com/WXjzcccc/go-mmkv/blob/632d1639bb16860e5f21567d9df3a07a45c3ed38/vault.go#L102-L106)), which misreads
  a store whose varint is shorter.

## License

MIT. See [LICENSE](LICENSE).
