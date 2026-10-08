#!/usr/bin/env python3
"""
Convert V20 JSON tests to gzip-compressed MOO 1.0 files.
"""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import gzip
import json
from pathlib import Path
import shutil
import struct
import tempfile
import time


REG_ORDER = (
    'ax', 'bx', 'cx', 'dx',
    'cs', 'ss', 'ds', 'es',
    'sp', 'bp', 'si', 'di',
    'ip', 'flags',
)

SEGMENT = {name: i for i, name in enumerate(('ES', 'SS', 'CS', 'DS', '--'))}

BUS = {
    name: i
    for i, name in enumerate(
        ('INTA', 'IOR', 'IOW', 'MEMR', 'MEMW', 'HALT', 'CODE', 'PASV')
    )
}

T_STATE = {name: i for i, name in enumerate(('Ti', 'T1', 'T2', 'T3', 'T4', 'Tw'))}

QUEUE_OP = {name: i for i, name in enumerate(('-', 'F', 'E', 'S'))}

STATUS = {
    ''.join(
        letter if mask & (4 >> i) else '-'
        for i, letter in enumerate('RAW')
    ): mask
    for mask in range(8)
}

U32 = struct.Struct('<I')
CYCLE = struct.Struct('<BIBBBBHBBBB')
RAM = struct.Struct('<IB')
CHUNK = struct.Struct('<4sI')
HEADER = struct.Struct('<BBHI4s')

TEST_KEYS = {'name', 'bytes', 'initial', 'final', 'cycles', 'hash', 'idx'}


def iter_tests(path):
    """Read a JSON array incrementally, including delimiter/EOF validation."""
    opener = gzip.open if path.suffix.lower() == '.gz' else open
    decoder = json.JSONDecoder()

    with opener(path, 'rt', encoding='utf-8') as source:
        buffer = ''
        offset = 0
        eof = False

        def refill():
            nonlocal buffer, offset, eof

            block = source.read(1024 * 1024)
            buffer = buffer[offset:] + block
            offset = 0
            eof = not block

        def peek():
            nonlocal offset

            while True:
                while offset < len(buffer) and buffer[offset] in ' \r\n\t':
                    offset += 1

                if offset < len(buffer):
                    return buffer[offset]

                if eof:
                    return ''

                refill()

        if peek() != '[':
            raise ValueError(f'{path}: expected a JSON array')

        offset += 1

        if peek() != ']':
            while True:
                if peek() != '{':
                    raise ValueError(f'{path}: expected a test object')

                while True:
                    try:
                        test, end = decoder.raw_decode(buffer, offset)
                        break
                    except json.JSONDecodeError:
                        if eof:
                            raise

                        refill()

                offset = end
                yield test

                delimiter = peek()

                if delimiter == ']':
                    break

                if delimiter != ',':
                    raise ValueError(f'{path}: expected comma or closing bracket')

                offset += 1

        offset += 1

        if peek():
            raise ValueError(f'{path}: trailing data after JSON array')


def chunk(tag, payload):
    return CHUNK.pack(tag, len(payload)) + payload


def counted_bytes(tag, payload):
    return chunk(tag, U32.pack(len(payload)) + payload)


def file_header(count):
    return chunk(b'MOO ', HEADER.pack(1, 0, 0, count, b'V20 '))


def encode_state(state, initial=False):
    if set(state) != {'regs', 'ram', 'queue'}:
        raise ValueError(f'Unexpected state fields: {set(state)}')

    regs = state['regs']

    if set(regs) - set(REG_ORDER) or (initial and set(regs) != set(REG_ORDER)):
        raise ValueError(f'Unexpected register set: {set(regs)}')

    mask = sum(1 << i for i, name in enumerate(REG_ORDER) if name in regs)
    values = [regs[name] for name in REG_ORDER if name in regs]
    registers = struct.pack('<' + 'H' * (1 + len(values)), mask, *values)

    # Preserve RAM access order, including any repeated addresses.
    ram = U32.pack(len(state['ram'])) + b''.join(RAM.pack(*entry) for entry in state['ram'])

    return (
        chunk(b'REGS', registers)
        + chunk(b'RAM ', ram)
        + counted_bytes(b'QUEU', bytes(state['queue']))
    )


def encode_test(test):
    if set(test) != TEST_KEYS:
        raise ValueError(f'Unexpected test fields: {set(test)}')

    digest = bytes.fromhex(test['hash'])

    if len(digest) != 20 or digest.hex() != test['hash']:
        raise ValueError('Expected a 40-character lowercase SHA-1 identifier')

    cycles = bytearray(4 + len(test['cycles']) * CYCLE.size)
    U32.pack_into(cycles, 0, len(test['cycles']))
    offset = 4

    for cycle in test['cycles']:
        pin, address, seg, mem, io, bhe, data, bus, t_state, q_op, q_byte = cycle

        CYCLE.pack_into(
            cycles,
            offset,
            pin,
            address,
            SEGMENT[seg],
            STATUS[mem],
            STATUS[io],
            bhe,
            data,
            BUS[bus],
            T_STATE[t_state],
            QUEUE_OP[q_op],
            q_byte,
        )

        offset += CYCLE.size

    payload = b''.join((
        U32.pack(test['idx']),
        counted_bytes(b'NAME', test['name'].encode('ascii')),
        counted_bytes(b'BYTS', bytes(test['bytes'])),
        chunk(b'INIT', encode_state(test['initial'], initial=True)),
        chunk(b'FINA', encode_state(test['final'])),
        chunk(b'CYCL', cycles),
        chunk(b'HASH', digest),
    ))

    return chunk(b'TEST', payload)


def convert_file(source, destination):
    count = cycles = 0
    temporary = None

    try:
        with tempfile.TemporaryFile() as raw:
            raw.write(file_header(0))

            for test in iter_tests(source):
                try:
                    raw.write(encode_test(test))
                except (KeyError, TypeError, ValueError, struct.error) as error:
                    raise ValueError(f'{source.name}: test {count}: {error}') from error

                count += 1
                cycles += len(test['cycles'])

            if not count:
                raise ValueError(f'{source}: no tests')

            raw_size = raw.tell()
            raw.seek(0)
            raw.write(file_header(count))
            raw.seek(0)

            with tempfile.NamedTemporaryFile(
                dir=destination.parent,
                suffix='.tmp',
                delete=False,
            ) as compressed:
                temporary = Path(compressed.name)

                with gzip.GzipFile(
                    filename='',
                    mode='wb',
                    fileobj=compressed,
                    compresslevel=9,
                    mtime=0,
                ) as zipped:
                    shutil.copyfileobj(raw, zipped, length=1024 * 1024)

        temporary.replace(destination)

        return count, cycles, raw_size, destination.stat().st_size

    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('src', type=Path, help='JSON/.json.gz file or directory')
    parser.add_argument('out', type=Path, help='Output directory for .MOO.gz files')
    parser.add_argument(
        '--workers',
        type=int,
        default=1,
        help='Concurrent files (default: 1)',
    )

    args = parser.parse_args()

    if args.workers < 1:
        parser.error('--workers must be positive')

    if args.src.is_dir():
        sources = sorted(
            p for p in args.src.iterdir()
            if p.is_file()
            and p.name != 'metadata.json'
            and p.name.lower().endswith(('.json', '.json.gz'))
        )
    elif args.src.is_file():
        sources = [args.src]
    else:
        parser.error('Source does not exist')

    if not sources:
        parser.error('No JSON test files found')

    jobs = []

    for source in sources:
        name = source.name

        if name.lower().endswith('.gz'):
            name = name[:-3]

        if not name.lower().endswith('.json'):
            parser.error(f'Not a JSON test file: {source}')

        # Retain opcode extensions: F7.7.json.gz -> F7.7.MOO.gz.
        jobs.append((source, args.out / (name[:-5] + '.MOO.gz')))

    if len({output.name.casefold() for _, output in jobs}) != len(jobs):
        parser.error('Multiple inputs map to the same output filename')

    args.out.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    totals = [0, 0, 0, 0]

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(convert_file, source, output): source
            for source, output in jobs
        }

        for done, future in enumerate(as_completed(futures), 1):
            result = future.result()
            totals = [a + b for a, b in zip(totals, result)]

            print(
                f'[{done}/{len(jobs)}] {futures[future].name}: {result[0]:,} tests, '
                f'{result[1]:,} cycles',
                flush=True,
            )

    if args.src.is_dir():
        metadata = args.src / 'metadata.json'

        if metadata.is_file() and metadata.resolve() != (args.out / metadata.name).resolve():
            shutil.copyfile(metadata, args.out / metadata.name)

    print(
        f'Completed {len(jobs)} files: {totals[0]:,} tests, {totals[1]:,} cycles, '
        f'{totals[2]:,} MOO bytes, {totals[3]:,} gzip bytes '
        f'in {time.monotonic() - start:.1f}s.',
        flush=True,
    )


if __name__ == '__main__':
    main()
