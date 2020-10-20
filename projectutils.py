import os
import subprocess
import sys

from data import Project, ProjectBuildResult, DisassemblerDb, AlternativeEncodingEntry


class DisassemblyOutputParseError(BaseException):
    pass


def parse_disassembly_line(ln: str):
    try:
        address = int(ln[:8], base=16)
        bytes_ = bytes.fromhex(ln[10:32])
    except ValueError:
        raise DisassemblyOutputParseError()

    if len(bytes_) == 0:
        raise DisassemblyOutputParseError()

    rest = ln[32:]
    space_pos = rest.find(" ")
    if space_pos > 0:
        mnemonic = rest[:space_pos].strip()
        operands = rest[space_pos + 1:].strip()
    else:
        mnemonic = rest
        operands = ""

    return (address, bytes_, mnemonic, operands)


# TODO: this is specific to AsmProj and should be moved there!
def build_project(project: Project, disassembler_db: DisassemblerDb):
    project_path = project.dir
    new_information = False

    print(f"Building project in {project_path}...")

    with subprocess.Popen(["make", "-j", str(os.cpu_count())], cwd=project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, errors="replace") as p:
        (stdout_data, stderr_data) = p.communicate(input=None, timeout=None)

        if stderr_data:
            # ../asm/text_00401000.s:523648: Error: invalid instruction suffix for `cmpsd'
            print("Compilation error:", file=sys.stderr)
            print(stderr_data, file=sys.stderr)
            raise Exception("Compilation error")

        assert p.returncode == 0

    # compare disassembly of input & output

    diff = subprocess.run(["diff", "input.s", "build/output.s"], cwd=project_path, capture_output=True)

    if diff.returncode != 0:
        # manually find differences
        with open(project_path / "input.s", "rt") as f1, open(project_path / "build/output.s", "rt") as f2:
            for l1, l2 in zip(f1, f2):
                if l1 == l2:
                    continue

                cmp = f"EXPECT: {l1.rstrip()}\nGOT:    {l2.rstrip()}"

                try:
                    address1, bytes1, mnemonic1, operands1 = parse_disassembly_line(l1)
                    address2, bytes2, mnemonic2, operands2 = parse_disassembly_line(l2)

                    # keep in mind that mnemonics might parse as empty strings for line #2 of long instruction

                    # if not mnemonic1 and not mnemonic2:
                    #     # second line of long instruction, e.g.
                    #     # 4b637b:	c7 85 5c ff ff ff 10 	mov    DWORD PTR [ebp-0xa4],0x645810
                    #     # 4b6382:	58 64 00
                    #     print(f"Note: {address1:08X}h: ignoring line without mnemonic\n{cmp}")
                    #     continue

                    # Perhaps just an encoding variation?
                    # Allowing different lengths allows handling also cases like the following:
                    # Error: 0061A71B: disassembly mismatch
                    # EXPECT:   61a71b:	05 00 00 00 00       	add    eax,0x0
                    # GOT:      61a71b:	83 c0 00             	add    eax,0x0
                    # TBD if this is a good idea, though
                    if mnemonic1 and address1 == address2 and (mnemonic1, operands1) == (mnemonic2, operands2): # and len(bytes1) == len(bytes2)
                        if project.disassembler_db_snapshot.has_alternative_encoding_entry(mnemonic1, operands1, bytes1):
                            print(f"Note: {address1:08X}h: attempted alternative encoding of '{mnemonic1} {operands1}' failed. Marking bytes as do-not-disassemble")

                            disassembler_db.set_alternative_encoding_entry(mnemonic1, operands1, bytes1, address1, AlternativeEncodingEntry.ALTERNATIVE_ENCODING_FAILED)
                            # TODO: mark bytes as do-not-disassemble in bitmap as well
                        else:
                            print(f"Note: {address1:08X}h: discovered alternative encoding of '{mnemonic1} {operands1}': {bytes1.hex()} vs {bytes2.hex()}")
                            disassembler_db.set_alternative_encoding_entry(mnemonic1, operands1, bytes1, address1, AlternativeEncodingEntry.ALTERNATIVE_ENCODING_ACTIVE)

                        new_information = True
                        continue

                    # A longer encoding is expected
                    # unfortunately we cannot compare operands, because a relative jump (for example) will point to the wrong place if the length mis-matches
                    if mnemonic1 and address1 == address2 and mnemonic1 == mnemonic2 and len(bytes1) > len(bytes2):
                        if (len(bytes1) == 5 and mnemonic1 == "jmp") or (len(bytes1) == 6 and mnemonic1 in {"je", "jg", "jge", "jle", "jne"}):
                            print(f'Note: {address1:08X}h: near-encoding of "{mnemonic1}" was expected, we generated short-encoding; force X86_JUMP_REL32')
                            disassembler_db.set_alternative_encoding_entry(mnemonic1, operands1, bytes1, address1, AlternativeEncodingEntry.X86_JUMP_REL32)
                            new_information = True
                            continue

                        print(f"Error: {address1:08X}: instruction encoding mismatch\n{cmp}")
                        continue
                except DisassemblyOutputParseError:
                    pass

                try:
                    address1, bytes1, mnemonic1, operands1 = parse_disassembly_line(l1)
                    address2, bytes2, mnemonic2, operands2 = parse_disassembly_line(l2)

                    if address1 == address2:
                        print(f"Error: {address1:08X}: disassembly mismatch\n{cmp}")
                        continue
                    else:
                        print(f"Error: {address1:08X}: disassembly has diverged\n{cmp}")
                        break
                except DisassemblyOutputParseError:
                    pass

                raise Exception(f"Disassembly mis-match\n{cmp}")

        success = False
    else:
        success = True

    # TODO: if fails, look for equal-length substitutions with matching instruction + operands -> these are alt encodings

    # matches = ;

    return ProjectBuildResult(success=success, new_information=new_information)
