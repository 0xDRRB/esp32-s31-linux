#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Extract the pinned PP submission routine with a private post-result adapter.

Retain the pinned descriptor/security protocol and branch layout. Replace its
two unprotected list appends with a bounded local-critical helper, retain the
notification value before ownership publication, and redirect the final
pp_post result. SDK callers retain the original function.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import subprocess


def extract(data):
    if data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('expected little-endian ELF32')
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    if h[1:3] != (1, 243) or h[11] != 40:
        raise ValueError('expected RISC-V relocatable object')
    sections = [struct.unpack_from('<10I', data, h[6] + i * 40)
                for i in range(h[12])]

    def string(section, offset):
        start = sections[section][4] + offset
        return data[start:data.index(0, start)].decode()

    table = next(s for s in sections if s[1] == 2)
    symbols = [struct.unpack_from('<IIIBBH', data, table[4] + i * 16)
               for i in range(table[5] // 16)]
    names = [string(table[6], s[0]) for s in symbols]
    function = symbols[names.index('ppTxPkt')]
    section = function[5]
    code_section = sections[section]
    code = data[code_section[4]:code_section[4] + code_section[5]]
    if function[1] != 0 or function[2] != len(code):
        raise ValueError('submission function must occupy its own section')
    # This private ABI was audited against the linked SDK and revision-0 ROM.
    if hashlib.sha256(code).hexdigest() != 'd1630ac84da6b8982e7f253d5fb50dee4cdc557effc43f878def602c80bc0a50':
        raise ValueError('PP submission routine changed; re-audit its ownership contract')
    # PP can consume/recycle EB as soon as enqueue restores interrupts. The
    # original routine reads meta+4 twice after publication, including after
    # lmacIsIdle. Retain that value in the unused stack word0 before linking;
    # neither EB nor its metadata may be dereferenced by the producer again.
    # Keep instruction lengths and all original branch destinations unchanged.
    code = bytearray(code)
    for offset, original, replacement in (
        (0x138, 0x4348, 0x4502),  # lw a0,4(a4) -> c.lwsp a0,0(sp)
        (0x148, 0x585c, 0x0001),  # lw a5,52(s0) -> c.nop
        (0x14e, 0x43c8, 0x4502),  # lw a0,4(a5) -> c.lwsp a0,0(sp)
    ):
        if struct.unpack_from('<H', code, offset)[0] != original:
            raise ValueError('post-publication metadata instruction changed')
        struct.pack_into('<H', code, offset, replacement)
    reloc_section = next(s for s in sections if s[1] == 4 and s[7] == section)
    relocs = [struct.unpack_from('<IIi', data, reloc_section[4] + i * 12)
              for i in range(reloc_section[5] // 12)]
    relocation_names = {16: 'BRANCH', 17: 'JAL', 18: 'CALL', 19: 'CALL_PLT',
                        26: 'HI20', 27: 'LO12_I', 28: 'LO12_S',
                        44: 'RVC_BRANCH', 45: 'RVC_JUMP'}
    rodata = set()
    post_count = 0
    lines = ['/* Generated from the pinned SDK pp.o. Do not edit. */',
             '.option norelax', '.section .text.s31_sm_pp_submit,"ax",@progbits',
             '.balign 2', '.global s31_sm_pp_submit',
             '.type s31_sm_pp_submit,@function', 's31_sm_pp_submit:']

    def emit_bytes(payload):
        for i in range(0, len(payload), 16):
            lines.append('.byte ' + ','.join(str(x) for x in payload[i:i + 16]))

    # SDK callers supply exclusion around the intrusive queue append. Our
    # lower-priority native submitter can otherwise be preempted by PP after
    # publishing *tail but before updating tail: PP empties head, then the
    # submitter publishes a stale tail into the removed EB. Keep every original
    # offset/branch displacement. Snapshot the ready-path notification before
    # ownership publication; the waiting path has no subsequent metadata use.
    appends = ((0xfa, 0x128, 0), (0x174, 0x1a6, 1))
    cursor = 0
    for begin, end, waiting in appends:
        emit_bytes(code[cursor:begin])
        lines.extend(['.option push', '.option norvc'])
        size = 16
        if not waiting:
            lines.extend(['lw a4,52(s0)', 'lw a4,4(a4)', 'sw a4,0(sp)'])
            size += 12
        lines.extend(['addi a0,s0,0', f'addi a1,zero,{waiting}',
                      'call s31_sm_pp_enqueue',
                      '.option pop', f'.fill {(end-begin-size)//2},2,0x0001'])
        cursor = end
    emit_bytes(code[cursor:])
    for offset, info, addend in relocs:
        kind, index = info & 255, info >> 8
        if any(begin <= offset < end for begin, end, _ in appends):
            continue
        if kind == 51:  # Keep the original instruction layout; no relaxation.
            continue
        if kind not in relocation_names or offset >= len(code):
            raise ValueError('unexpected submission relocation')
        symbol = symbols[index]
        if symbol[5] == section:
            if any(begin < symbol[1]+addend < end for begin, end, _ in appends):
                raise ValueError('branch targets replaced queue append interior')
            target = f's31_sm_pp_submit+{symbol[1]}'
        elif symbol[3] >> 4 == 0:
            target_section = sections[symbol[5]]
            if target_section[1] != 1 or target_section[2] & 7 != 2:
                raise ValueError('unexpected local submission dependency')
            # The retained strings must not themselves contain relocations.
            if any(s[1] == 4 and s[7] == symbol[5] for s in sections):
                raise ValueError('relocated local submission data')
            rodata.add(symbol[5])
            target = f'.Ls31_pp_data_{symbol[5]}+{symbol[1]}'
        else:
            target = names[index]
            if target == 'pp_post':
                if kind not in (18, 19) or offset != 0x15c or addend:
                    raise ValueError('unexpected PP post callsite')
                target = 's31_sm_pp_post_result'
                post_count += 1
        lines.append(f'.reloc s31_sm_pp_submit+{offset},'
                     f'R_RISCV_{relocation_names[kind]},{target}+({addend})')
    if post_count != 1:
        raise ValueError('expected exactly one PP post tail call')
    lines.append(f'.size s31_sm_pp_submit,{len(code)}')
    for index in sorted(rodata):
        s = sections[index]
        lines.extend([f'.section .rodata.s31_sm_pp_submit.{index},"a",@progbits',
                      f'.balign {max(1, s[8])}', f'.Ls31_pp_data_{index}:'])
        emit_bytes(data[s[4]:s[4] + s[5]])
    lines.append('.section .note.GNU-stack,"",@progbits')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ar', required=True)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = subprocess.check_output([args.ar, 'p', args.archive, 'pp.o'])
    args.output.write_text(extract(data))


if __name__ == '__main__':
    main()
