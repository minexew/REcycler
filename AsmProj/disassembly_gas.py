import capstone

from asmutils import gnuas_escape_label
from data import DisassemblerDb, RawChunk, UnknownChunk, BasicBlock, AlternativeEncodingEntry

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def disassemble_for_GAS(chunks, file, disassembler_db: DisassemblerDb, labels_db: dict = None, use_labels=True):
    esc = gnuas_escape_label

    # these are assumed to never appear in valid (win32) code, so they can be used as data hints earlier in the pipeline
    # TODO: move out of code
    forbidden_sequences = {
        # Error: 0044E522: instruction encoding mismatch
        # EXPECT:   44e522:	66 f3 ab             	rep stos WORD PTR es:[edi],ax
        # GOT:      44e522:	f3 ab                	rep stos DWORD PTR es:[edi],eax
        b"\x66\xf3\xab",            # TODO: isolate & file capstone bug

        # Error: 00545C94: instruction encoding mismatch
        # EXPECT:   545c94:       3b 4c 84 00             cmp    ecx,DWORD PTR [esp+eax*4+0x0]
        # GOT:      545c94:       3b 0c 84                cmp    ecx,DWORD PTR [esp+eax*4]
        b"\x3B\x4C\x84\x00",        # TODO: handle systematically

        # Error: 006234C1: disassembly mismatch
        # EXPECT:   6234c1:	      8d 49 00             	lea    ecx,[ecx+0x0]
        # GOT:      6234c1:	      8d 09                	lea    ecx,[ecx]
        b"\x8D\x49\x00",            # TODO: handle systematically

        # Error: 00545C68: instruction encoding mismatch
        # EXPECT:   545c68:       89 44 24 00             mov    DWORD PTR [esp+0x0],eax
        # GOT:      545c68:       89 04 24                mov    DWORD PTR [esp],eax
        b"\x89\x44\x24\x00",        # TODO: handle systematically

        # Error: 00403F2D: instruction encoding mismatch
        # EXPECT:   403f2d:       89 4c 24 00             mov    DWORD PTR [esp+0x0],ecx
        # GOT:      403f2d:       89 0c 24                mov    DWORD PTR [esp],ecx
        b"\x89\x4c\x24\x00",        # TODO: handle systematically

        # Error: 004446B3: disassembly mismatch
        # EXPECT:   4446b3:       8d 44 24 00             lea    eax,[esp+0x0]
        # GOT:      4446b3:       8d 04 24                lea    eax,[esp]
        b"\x8D\x44\x24\x00",        # TODO: handle systematically

        # Error: 00545C0B: instruction encoding mismatch
        # EXPECT:   545c0b:       89 54 24 00             mov    DWORD PTR [esp+0x0],edx
        # GOT:      545c0b:       89 14 24                mov    DWORD PTR [esp],edx
        b"\x89\x54\x24\x00",        # TODO: handle systematically

        # Error: 00545C51: instruction encoding mismatch
        # EXPECT:   545c51:       8b 54 84 00             mov    edx,DWORD PTR [esp+eax*4+0x0]
        # GOT:      545c51:       8b 14 84                mov    edx,DWORD PTR [esp+eax*4]
        b"\x8B\x54\x84\x00",        # TODO: handle systematically

        # Error: 005C0004: instruction encoding mismatch
        # EXPECT:   5c0004:       8d 4c 24 00             lea    ecx,[esp+0x0]
        # GOT:      5c0004:       8d 0c 24                lea    ecx,[esp]
        b"\x8D\x4C\x24\x00",        # TODO: handle systematically

        # Error: 10018CF6: instruction encoding mismatch
        # EXPECT: 10018cf6:	8d 54 24 00          	lea    edx,[esp+0x0]
        # GOT:    10018cf6:	8d 14 24             	lea    edx,[esp]
        b"\x8D\x54\x24\x00",        # TODO: handle systematically
    }

    # these are assumed to never appear in valid (win32) code, so they can be used as data hints earlier in the pipeline
    # TODO: move out of code
    forbidden_mnemonics = {
        # "salc",         # D6
        "fnstcw",           # https://github.com/aquynh/capstone/issues/1611
        "fnstsw",           # https://github.com/aquynh/capstone/issues/1611
    }

    def emit_bytes(address, bytes, note=""):
        for b in bytes:
            if labels_db is not None and address in labels_db:
                label = labels_db[address]
                if label.usages["call"] > 0:        # TODO: label.type == FUNCTION
                    print(file=file)
                print(f"{esc(label.name)}:", file=file)

            print(f"    {'.byte':8s} 0x{b:02x} {'':35s} /* 0x{address:08x} {b:02X} {note} */", file=file)
            address += 1
        return address

    last_address = chunks[0].start

    for chunk in chunks:
        print(file=file)
        print(f"/* chunk {chunk} */", file=file)

        if isinstance(chunk, RawChunk) or isinstance(chunk, UnknownChunk):
            # TODO: use information gained from labels_db to declare other types, e.g. words & dwords
            #       some preprocessing will be needed to ensure that they following bytes of the variable end up in the some DataChunk
            assert chunk.start == last_address
            last_address = emit_bytes(chunk.start, chunk.bytes)
        elif isinstance(chunk, BasicBlock):
            chunk_start, chunk_end, chunk_bytes = chunk.start, chunk.end, chunk.bytes

            for insn in md.disasm(chunk_bytes, chunk_start):
                assert insn.address == last_address

                (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str
                bytes = chunk_bytes[address - chunk_start:address - chunk_start + size]

                alternative_encoding = disassembler_db.try_get_alternative_encoding_entry(bytes)

                if alternative_encoding == AlternativeEncodingEntry.X86_JUMP_REL32:
                    # TODO: for one, we should be able to detect this (whenever instruction is 0F / E9, but destination is close)
                    # TODO: for two, instead of a bunch of bytes, we should emit DB, relative DD, and a comment
                    last_address = emit_bytes(address, bytes, f"{mnemonic} rel32 {op_str}")
                    continue

                if alternative_encoding == AlternativeEncodingEntry.ALTERNATIVE_ENCODING_FAILED:
                    last_address = emit_bytes(address, bytes, f'alt encoding of "{mnemonic} {op_str}"')
                    continue

                if mnemonic in forbidden_mnemonics:
                    last_address = emit_bytes(address, bytes, f"forbidden instruction {mnemonic}")
                    continue

                if bytes in forbidden_sequences:
                    last_address = emit_bytes(address, bytes, f"forbidden byte sequence {bytes.hex()}")
                    continue

                if labels_db is not None and address in labels_db:
                    label = labels_db[address]
                    # if label.usages["call"] > 0:        # TODO: label.type == FUNCTION
                    #     print(file=file)
                    print(f"{esc(label.name)}:", file=file)

                # preprocess known calls etc.
                if labels_db is not None and use_labels:
                    # watch out for shit like "dword ptr [data_4e4618], offset data_4e4618"
                    for operand in insn.operands:
                        # print("; OPERAND", operand.type, f"0x{operand.imm:08x}", file=file)

                        # value-at-address references
                        if operand.type == capstone.x86.X86_OP_MEM:
                            if operand.mem.disp in labels_db:
                                # massive hack -- find the stuff and replace
                                formatted = f"0x{operand.mem.disp:x}"
                                assert formatted in op_str
                                op_str = op_str.replace(formatted, esc(labels_db[operand.mem.disp].name), 1)

                        # address references
                        if operand.type == capstone.x86.X86_OP_IMM:
                            if operand.imm in labels_db:
                                # massive hack -- find the stuff and replace
                                formatted = f"0x{operand.imm:x}"
                                assert formatted in op_str
                                if capstone.x86.X86_GRP_CALL in insn.groups or capstone.x86.X86_GRP_JUMP in insn.groups:
                                    op_str = op_str.replace(formatted, esc(labels_db[operand.imm].name), 1)
                                else:
                                    op_str = op_str.replace(formatted, "offset " + esc(labels_db[operand.imm].name), 1)

                # TODO: move out of code
                replacements = {
                    "cmpsd": "cmps",
                    "popal": "popa",
                    "pushal": "pusha",
                    "movsd": "movs",
                    "repe cmpsd": "repe cmps",
                    "rep movsd": "rep movs",
                }

                # now handled in a more data-oriented way
                specific_encodings = {
                    # b"\x03\xCA": "add.s",           # add ecx,edx
                    # b"\x33\xC0": "xor.s",           # xor eax, eax
                    # b"\x33\xD2": "xor.s",           # xor edx, edx
                    # b"\x33\xF6": "xor.s",           # xor esi, esi
                    # b"\x8A\xD4": "mov.s",           # mov dl, ah
                    # b"\x8B\xC8": "mov.s",           # mov ecx, eax
                    # b"\x8B\xEC": "mov.s",           # mov ebp, esp
                }

                if alternative_encoding == AlternativeEncodingEntry.ALTERNATIVE_ENCODING_ACTIVE:
                    mnemonic = mnemonic + ".s"
                elif bytes in specific_encodings:
                    mnemonic = specific_encodings[bytes]
                elif mnemonic in replacements:
                    # print("REPLACE", mnemonic)
                    mnemonic = replacements[mnemonic]

                op_str = op_str.replace("xword", "tbyte")

                bytes_hex = " ".join(["%02X" % byte for byte in bytes])
                # print("" % (address, bytes_hex), file=file)

                print(f"    {mnemonic:11s} {op_str:40} /* 0x{address:08x} {bytes_hex} */", file=file)
                last_address += len(bytes)

        print(f"/* end chunk {chunk} */", file=file)