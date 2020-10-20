from typing import Optional

import capstone

from data import RawChunk, BasicBlock, Label, UnknownChunk, Chunk, CpuArch
from AsmProj.disassembly_gas import md      # FIXME bad, bad dependency

md.detail = True


def is_end_of_chunk(insn):
    return insn.mnemonic in {"jmp", "ret"}


def try_make_code_chunk(chunk, labels_db: dict, pe) -> (Optional[Chunk], Chunk):
    assert isinstance(chunk, UnknownChunk)
    arch = CpuArch.CPU_X86_32       # TODO: un-hardcode

    offset = chunk.start

    code_refs = set()
    data_refs = set()

    # check for x86 function prologue
    if chunk.bytes.startswith(b"\x55\x8B\xEC"):       # push ebp; mov ebp, esp
        label = get_label_for_address(labels_db, chunk.start)
        label.flags.add(Label.FLAG_FUNCTION_PROLOGUE)

    for insn in md.disasm(chunk.bytes, chunk.start):
        (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str

        if labels_db is not None:
            for operand in insn.operands:
                if operand.type == capstone.x86.X86_OP_MEM:
                    label = get_label_for_address(labels_db, operand.mem.disp, pe=pe)

                    if label and operand.size in {1, 2, 4, 8}:
                        label.usages["data" + str(operand.size)] += 1
                        data_refs.add(operand.mem.disp)

                if operand.type == capstone.x86.X86_OP_IMM:
                    label = get_label_for_address(labels_db, operand.imm, pe=pe)

                    if label:
                        if capstone.x86.X86_GRP_CALL in insn.groups:
                            label.usages["call"] += 1
                            code_refs.add(operand.imm)
                        elif capstone.x86.X86_GRP_JUMP in insn.groups:
                            label.usages["jump"] += 1
                            code_refs.add(operand.imm)
                        else:
                            label.usages["imm"] += 1
                            data_refs.add(operand.imm)

        offset = address + size

        if is_end_of_chunk(insn):
            break

    if offset > chunk.start:
        code_chunk = BasicBlock(chunk.section_name, chunk.start, offset, chunk.bytes[:offset - chunk.start],
                                arch=arch, code_refs=code_refs, data_refs=data_refs)
    else:
        code_chunk = None

    if offset < chunk.end:
        rest_chunk = UnknownChunk(chunk.section_name, offset, chunk.end, chunk.bytes[offset - chunk.start:])
    else:
        rest_chunk = None

    return code_chunk, rest_chunk

def get_label_for_address(labels_db, address, pe=None) -> Optional[Label]:
    """
    Find or create a label in database. If a PE file is supplied, the label will be only created if it falls into one
    of its sections.
    """

    if address in labels_db:
        return labels_db[address]

    # check if it falls within code, data, etc...
    if pe is not None:
        for section in pe.sections:
            start = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            end = start + section.Misc_VirtualSize

            if address >= start and address < end:
                section_name = section.Name.decode(errors="ignore")

                # FIXME: this is a hack; we should not get section data directly from PE here,
                #        but instead pass ours with proper .bss
                if section_name == ".data\0\0\0":
                    if address >= start + section.SizeOfRawData:
                        section_name = ".bss"
                else:
                    # technically not invalid, but very suspicious
                    assert address < start + section.SizeOfRawData

                labels_db[address] = Label(f"{section_name[1:5]}_{address:06x}", address, origin="code")
                return labels_db[address]
    else:
        labels_db[address] = Label(f"unk_{address:06x}", address, origin="code")
        return labels_db[address]

    return None


# def detect_chunks(image_base, text_virtualaddress, text):
#     code_chunks = []
#     offset = image_base + text_virtualaddress
#
#     while offset < image_base + text_virtualaddress + len(text):
#         chunk_start = offset
#         print(f"SCAN CHUNK {chunk_start:08x}")
#
#         for insn in md.disasm(text[chunk_start - (image_base + text_virtualaddress):], offset):
#             (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str
#             offset = address + size
#
#         if offset > chunk_start:
#             code_chunks.append(CodeChunk(chunk_start, offset, text[chunk_start - (image_base + text_virtualaddress):offset - (image_base + text_virtualaddress)]))
#
#         if offset < image_base + text_virtualaddress + len(text):
#             in_text = offset - (image_base + text_virtualaddress)
#             code_chunks.append(RawChunk(offset, offset + 1, text[in_text:in_text + 1]))
#             offset += 1
#
#     return code_chunks


def fixup_chunks(chunks):
    print("fixup_chunks")
    arch = CpuArch.CPU_X86_32   # TODO: un-hardcode

    code_chunks = []

    for chunk in chunks:
        while chunk:
            if isinstance(chunk, UnknownChunk):
                offset = chunk.start

                for insn in md.disasm(chunk.bytes, offset):
                    (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str
                    offset = address + size

                # doesn't start with a valid instruction?
                if offset == chunk.start:
                    # cut off 1-byte RawChunk and continue
                    code_chunks.append(RawChunk(chunk.section_name, chunk.start, chunk.start + 1, chunk.bytes[:1]))

                    if len(chunk.bytes[1:]):
                        chunk = UnknownChunk(chunk.section_name, chunk.start + 1, chunk.end, chunk.bytes[1:])
                    else:
                        chunk = None

                    continue
                # empty space after last instruction?
                elif offset < chunk.end:
                    # carve out valid part
                    code_chunks.append(BasicBlock(chunk.section_name, chunk.start, offset, chunk.bytes[:offset - chunk.start], arch=arch))
                    # create 1-byte RawChunk
                    code_chunks.append(RawChunk(chunk.section_name, offset, offset + 1, chunk.bytes[offset - chunk.start:offset + 1 - chunk.start]))
                    # create UnknownChunk for anything that remains
                    if len(chunk.bytes[offset + 1 - chunk.start:]):
                        chunk = UnknownChunk(chunk.section_name, offset + 1, chunk.end, chunk.bytes[offset + 1 - chunk.start:])
                    else:
                        chunk = None
                    continue
                else:
                    chunk = BasicBlock(chunk.section_name, chunk.start, chunk.end, chunk.bytes, arch=arch)

            code_chunks.append(chunk)
            chunk = None

    print(f"fixup_chunks: {len(chunks)} => {len(code_chunks)}")
    return code_chunks

def detect_labels(pe, chunks, labels_db: dict):
    for chunk in chunks:
        if isinstance(chunk, BasicBlock):
            chunk_start, chunk_end, chunk_bytes = chunk.start, chunk.end, chunk.bytes

            for insn in md.disasm(chunk_bytes, chunk_start):
                (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str

                if labels_db is not None:
                    for operand in insn.operands:
                        if operand.type == capstone.x86.X86_OP_MEM:
                            label = get_label_for_address(labels_db, operand.mem.disp, pe=pe)

                            if label and operand.size in {1, 2, 4, 8}:
                                label.usages["data" + str(operand.size)] += 1

                        if operand.type == capstone.x86.X86_OP_IMM:
                            label = get_label_for_address(labels_db, operand.imm, pe=pe)

                            if label:
                                if capstone.x86.X86_GRP_CALL in insn.groups:
                                    label.usages["call"] += 1
                                elif capstone.x86.X86_GRP_JUMP in insn.groups:
                                    label.usages["jump"] += 1
                                else:
                                    label.usages["imm"] += 1

            assert address + size == chunk_end


def disassemble_for_nasm(chunks, file, labels_db: dict = None, use_labels=True):
    externs = set()
    my_labels = set()

    for label in sorted(labels_db.values()):
        if label.address < chunks[0].start:
            continue
        elif label.address < chunks[-1].end:
            my_labels.add(label.name)
        else:
            break

    # for chunk in chunks:
    #     if isinstance(chunk, CodeChunk):
    #         chunk_start, chunk_end, chunk_bytes = chunk.start, chunk.end, chunk.bytes
    #
    #         for insn in md.disasm(chunk_bytes, chunk_start):
    #             (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str
    #
    #             if labels_db is not None and address in labels_db:
    #                 label = labels_db[address]
    #                 my_labels.add(label.name)

    for chunk in chunks:
        if isinstance(chunk, BasicBlock):
            chunk_start, chunk_end, chunk_bytes = chunk.start, chunk.end, chunk.bytes

            for insn in md.disasm(chunk_bytes, chunk_start):
                (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str

                # preprocess known calls etc.
                if labels_db is not None and use_labels:
                    for operand in insn.operands:
                        # print("; OPERAND", operand.type, f"0x{operand.imm:08x}", file=file)

                        if operand.type == capstone.x86.X86_OP_MEM:
                            if operand.mem.disp in labels_db:
                                # massive hack -- find the stuff and replace
                                formatted = f"0x{operand.mem.disp:x}"
                                assert formatted in op_str
                                if labels_db[operand.mem.disp].name not in my_labels:
                                    externs.add(labels_db[operand.mem.disp].name)

                        if operand.type == capstone.x86.X86_OP_IMM:
                            if operand.imm in labels_db:
                                # massive hack -- find the stuff and replace
                                formatted = f"0x{operand.imm:x}"
                                assert formatted in op_str
                                if labels_db[operand.imm].name not in my_labels:
                                    externs.add(labels_db[operand.imm].name)

    for extern in externs:
        print(f"extern {extern}", file=file)

    for global_ in my_labels:
        print(f"global {global_}", file=file)

    forbidden_prefixes = {
                          b"\x2E\x2E",      # repeated 2E
                          b"\x2E\x40",      # cs inc eax
                          b"\x31\x40\x00",  # xor [eax+0x0],eax; TODO: we should be able to detect this
    }

    # these are assumed to never appear in valid (win32) code, so they can be used as data hints earlier in the pipeline
    forbidden_mnemonics = {
                           "bound",         # 62 xx xx xx xx xx
                           "fnstsw",        # valid instr, but has some decomp issues
                           "insb",          # 6Ch
                           "insd",          # 6Dh
                           "lcall",
                           "lds",
                           "les",
                           "ljmp",          # EA xx xx xx xx xx xx,
                           "outsb",         # 6E
                           "outsd",         # 6F
                           }
    implicit_argument_mnemonics = {"cmpsb",         # A6
                                   "cmpsd",
                                   "lodsb",         # AC
                                   "lodsd",         # AD
                                   "movsb",         # A4
                                   "movsd",         # A5
                                   "movsw",         # 66 A5
                                   "rep movsb", "rep movsd", "rep stosb", "rep stosd",
                                   "repe cmpsb",
                                   "repe cmpsd",    # F3 A7
                                   "repne scasb",
                                   "scasb",         # AE
                                   "scasd",         # AF
                                   "stosb",
                                   "stosd",
                                   "stosw",         # 66 AB
                                   }

    replacements = {
        "popal": "popa",
        "pushal": "pusha",
        # "cmpsd": "cmps",
        # "rep movsd": "rep movs",
    }

    specific_encodings = {
        # b"\x33\xC0": "xor.s",           # xor eax, eax
        # b"\x33\xF6": "xor.s",           # xor esi, esi
        # b"\x8B\xEC": "mov.s",           # mov ebp, esp
    }

    def emit_bytes(address, bytes):
        for b in bytes:
            if labels_db is not None and address in labels_db:
                label = labels_db[address]
                if label.usages["call"] > 0:        # TODO: label.type == FUNCTION
                    print(file=file)
                print(f"{label.name}:", file=file)

            print(f"    {'db':8s} 0x{b:02x} {'':35s} ; 0x{address:08x} {b:02X}", file=file)
            address += 1

    for chunk in chunks:
        if isinstance(chunk, RawChunk):
            # TODO: use information gained from labels_db to declare other types, e.g. words & dwords
            #       some preprocessing will be needed to ensure that they following bytes of the variable end up in the some DataChunk
            emit_bytes(chunk.start, chunk.bytes)
        elif isinstance(chunk, BasicBlock):
            chunk_start, chunk_end, chunk_bytes = chunk.start, chunk.end, chunk.bytes

            for insn in md.disasm(chunk_bytes, chunk_start):
                (address, size, mnemonic, op_str) = insn.address, insn.size, insn.mnemonic, insn.op_str
                bytes = chunk_bytes[address - chunk_start:address - chunk_start + size]

                # if bytes[0] == 0xdd:
                #     print(mnemonic, "|", op_str)

                # if mnemonic == "fnstsw" and "dword ptr" in operand:
                #     # bad disassembly?
                #     emit_bytes(address, bytes)
                #     continue

                if insn.mnemonic in forbidden_mnemonics or any(bytes.startswith(prefix) for prefix in forbidden_prefixes):
                    emit_bytes(address, bytes)
                    continue

                if labels_db is not None and address in labels_db:
                    label = labels_db[address]
                    if label.usages["call"] > 0:        # TODO: label.type == FUNCTION
                        print(file=file)
                    print(f"{label.name}:", file=file)

                # preprocess known calls etc.
                if labels_db is not None and use_labels:
                    for operand in insn.operands:
                        # print("; OPERAND", operand.type, f"0x{operand.imm:08x}", file=file)

                        if operand.type == capstone.x86.X86_OP_MEM:
                            if operand.mem.disp in labels_db:
                                # massive hack -- find the stuff and replace
                                formatted = f"0x{operand.mem.disp:x}"
                                assert formatted in op_str
                                op_str = op_str.replace(formatted, labels_db[operand.mem.disp].name)

                        if operand.type == capstone.x86.X86_OP_IMM:
                            if operand.imm in labels_db:
                                # massive hack -- find the stuff and replace
                                formatted = f"0x{operand.imm:x}"
                                assert formatted in op_str
                                op_str = op_str.replace(formatted, labels_db[operand.imm].name)

                bytes_hex = ' '.join(['%02X' % byte for byte in bytes])
                # print("" % (address, bytes_hex), file=file)

                if bytes in specific_encodings:
                    mnemonic = specific_encodings[bytes]
                elif mnemonic in replacements:
                    # print("REPLACE", mnemonic)
                    mnemonic = replacements[mnemonic]

                if mnemonic in implicit_argument_mnemonics:
                    op_str = ""
                # elif mnemonic.startswith("rep"):
                #     print(mnemonic, "|", op_str)

                op_str = op_str.replace("byte ptr", "byte").replace(
                                        #"movsd dword ptr", "movsd").replace(
                                        "dword ptr", "dword").replace(
                                        "eax, dword [", "eax, [").replace(
                                        "cs:[", "[cs:").replace(
                                        "ds:[", "[ds:").replace(
                                        "es:[", "[es:").replace(
                                        "fs:[", "[fs:").replace(
                                        "gs:[", "[gs:").replace(
                                        "ss:[", "[ss:").replace(
                                        "st(0)", "st0").replace(    # FIXME: better replace
                                        "st(1)", "st1").replace(
                                        "st(2)", "st2").replace(
                                        "st(3)", "st3").replace(
                                        "st(4)", "st4").replace(
                                        "st(5)", "st5").replace(
                                        "st(6)", "st6").replace(
                                        "st(7)", "st7").replace(
                                        "word ptr", "word").replace(
                                        "xmmword", "oword").replace(
                                        "xword", "tword")

                print(f"    {mnemonic:8s} {op_str:40} ; 0x{address:08x} {bytes_hex}", file=file)


# def detect_function_prologues(chunks, labels_db):
#     for chunk in chunks:
#         if isinstance(chunk, CodeChunk):
#             pos = 0
#
#             while True:
#                 # push ebp; mov ebp, esp
#                 pos = chunk.bytes.find(b"\x55\x8B\xEC", pos)
#
#                 if pos >= 0:
#                     label = get_label_for_address(labels_db, chunk.start + pos)
#                     label.flags.add(Label.FLAG_FUNCTION_PROLOGUE)
#                     # resume after the found occurence
#                     pos += 3
#                     continue
#
#                 # TODO: other kinds of prototyoes?
#
#                 break
