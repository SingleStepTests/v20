#!/usr/bin/env python3
"""
Convert a directory of .MOO/.MOO.gz tests back to JSON.
"""

import argparse
import binascii
import gzip
import json
import os
import struct


REG_ORDER = [
    'ax', 'bx', 'cx', 'dx',
    'cs', 'ss', 'ds', 'es',
    'sp', 'bp', 'si', 'di',
    'ip', 'flags'
]

SEGMENT_MAP = {0: "ES", 1: "SS", 2: "CS", 3: "DS", 4: "--"}

BUS_STATUS_MAP = {
    0: "INTA",
    1: "IOR",
    2: "IOW",
    3: "MEMR",
    4: "MEMW",
    5: "HALT",
    6: "CODE",
    7: "PASV",
}

T_STATE_MAP = {0: "Ti", 1: "T1", 2: "T2", 3: "T3", 4: "T4"}

QUEUE_OP_MAP = {0: "-", 1: "F", 2: "E", 3: "S"}

# Both memory and I/O flags use the same letters.
FLAG_CHARS = ['R', 'A', 'W']


def decode_bitfield3(bf: int) -> str:
    """
    Reconstruct a 3-character flag string from a 3-bit bitfield,
    using the letters ['R','A','W'] for bit positions 2,1,0.
    """
    out = []

    for i in range(3):
        bit = (bf >> (2 - i)) & 1
        out.append(FLAG_CHARS[i] if bit else '-')

    return ''.join(out)


def decode_regs(data: bytes) -> dict:
    bitmask, = struct.unpack_from('<H', data, 0)
    offset = 2
    regs = {}

    for i, name in enumerate(REG_ORDER):
        if bitmask & (1 << i):
            val, = struct.unpack_from('<H', data, offset)
            regs[name] = val
            offset += 2

    return regs


def decode_ram(data: bytes) -> list[list[int]]:
    count, = struct.unpack_from('<I', data, 0)
    offset = 4
    ram = []

    for _ in range(count):
        addr, byte = struct.unpack_from('<I B', data, offset)
        ram.append([addr, byte])
        offset += 5

    return ram


def decode_queue(data: bytes) -> list[int]:
    count, = struct.unpack_from('<I', data, 0)

    return list(data[4:4 + count])


def decode_cpu_state(data: bytes) -> dict:
    offset = 0
    end = len(data)
    state = {'regs': {}, 'ram': [], 'queue': []}

    while offset < end:
        tag = data[offset:offset + 4].decode('ascii')
        offset += 4

        length, = struct.unpack_from('<I', data, offset)
        offset += 4

        payload = data[offset:offset + length]
        offset += length

        if tag == 'REGS':
            state['regs'] = decode_regs(payload)
        elif tag == 'RAM ':
            state['ram'] = decode_ram(payload)
        elif tag == 'QUEU':
            state['queue'] = decode_queue(payload)

    return state


def decode_cycles(data: bytes) -> list:
    count, = struct.unpack_from('<I', data, 0)
    offset = 4
    rec_fmt = '<B I B B B B H B B B B'
    rec_size = struct.calcsize(rec_fmt)
    cycles = []

    for _ in range(count):
        fields = struct.unpack_from(rec_fmt, data, offset)
        offset += rec_size

        (
            pin, addr_latch, seg_i, mem_bf, io_bf, bhe,
            data_bus, bus_i, t_i, qop_i, qread,
        ) = fields

        cycles.append([
            pin,
            addr_latch,
            SEGMENT_MAP.get(seg_i, "--"),
            decode_bitfield3(mem_bf),
            decode_bitfield3(io_bf),
            bhe,
            data_bus,
            BUS_STATUS_MAP.get(bus_i, "PASV"),
            T_STATE_MAP.get(t_i, "Ti"),
            QUEUE_OP_MAP.get(qop_i, "-"),
            qread
        ])

    return cycles


def parse_moo_bytes(data: bytes) -> list[dict]:
    offset = 0

    if data[offset:offset + 4] != b'MOO ':
        raise ValueError("Not a MOO file")

    offset += 4
    hlen, = struct.unpack_from('<I', data, offset)
    offset += 4
    offset += hlen
    tests = []

    while offset < len(data):
        tag = data[offset:offset + 4].decode('ascii')
        offset += 4

        length, = struct.unpack_from('<I', data, offset)
        offset += 4

        payload = data[offset:offset + length]
        offset += length

        if tag != 'TEST':
            continue

        tidx, = struct.unpack_from('<I', payload, 0)
        poff = 4
        test = {'idx': tidx}

        while poff < len(payload):
            subt = payload[poff:poff + 4].decode('ascii')
            poff += 4

            slen, = struct.unpack_from('<I', payload, poff)
            poff += 4

            sp = payload[poff:poff + slen]
            poff += slen

            if subt == 'NAME':
                nl, = struct.unpack_from('<I', sp, 0)
                test['name'] = sp[4:4 + nl].decode('utf-8')
            elif subt == 'BYTS':
                cnt, = struct.unpack_from('<I', sp, 0)
                test['bytes'] = list(sp[4:4 + cnt])
            elif subt == 'INIT':
                test['initial'] = decode_cpu_state(sp)
            elif subt == 'FINA':
                test['final'] = decode_cpu_state(sp)
            elif subt == 'CYCL':
                test['cycles'] = decode_cycles(sp)
            elif subt == 'HASH':
                test['hash'] = binascii.hexlify(sp).decode('ascii')

        tests.append(test)

    return tests


def process_file(in_path: str, out_path: str):
    opener = gzip.open if in_path.lower().endswith('.gz') else open

    with opener(in_path, 'rb') as f:
        data = f.read()

    tests = parse_moo_bytes(data)

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(tests, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Convert all .MOO/.MOO.gz in a directory back to JSON files"
    )

    parser.add_argument('src_dir', help="Source directory with .MOO or .MOO.gz files")
    parser.add_argument('out_dir', help="Output directory for .json files")

    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    for fname in sorted(os.listdir(args.src_dir)):
        if fname.lower().endswith('.moo.gz'):
            base = fname[:-7]
        elif fname.lower().endswith('.moo'):
            base = fname[:-4]
        else:
            continue

        # Keep opcode extensions for both F7.7.MOO and F7.7.MOO.gz.
        in_path = os.path.join(args.src_dir, fname)
        out_fname = base + '.json'
        out_path = os.path.join(args.out_dir, out_fname)

        print(f"Processing {fname} -> {out_fname}...")
        process_file(in_path, out_path)


if __name__ == '__main__':
    main()
