from pathlib import Path
from typing import Iterable

import archinfo
import pyvex

from AsmCOutput.vex2c import irsb_to_C
from data import BasicBlock, CpuArch

CpuArch_to_pyvex_arch = {
    CpuArch.CPU_X86_32: archinfo.ArchX86()
}


def generate_AsmC(basic_blocks: Iterable[BasicBlock], projectpath: Path):
    bb_table = {}

    basedir = projectpath / "AsmC"
    basedir.mkdir(parents=True, exist_ok=True)

    MODULE = "Heroes3"
    ENTRY_POINT = 0x61a2b4

    with open(basedir / "program.c", "wt") as file:
        # file.write('#include "program.h"\n')
        file.write('#include "AsmC-x86-32.h"\n\n')
        file.write('#include <math.h>\n\n')
        file.write('#define cpu AsmC_state_x86_32\n\n')

        # Rewrite basic block
        for blk in basic_blocks:
            print(f"Processing {blk}")
            irsb = pyvex.block.IRSB(data=blk.bytes, mem_addr=blk.start, arch=CpuArch_to_pyvex_arch[blk.arch])

            function_name = f"blk_{irsb.addr:08X}"
            bb_table[irsb.addr] = function_name

            file.write(f"void {function_name}(void) {{\n")
            file.write(f"/*\n{irsb}\n*/\n\n")

            irsb_to_C(irsb, file=file)

            file.write("}\n\n")
            # break

    # Build table of basic blocks
    with open(basedir / "bb-table.c", "wt") as file:
        file.write('#include "AsmC-x86-32.h"\n\n')

        for addr, name in bb_table.items():
            file.write(f"void {name}(void);\n")

        file.write(f"\nconst AsmC_BbTableEntry32_t {MODULE}_bb_table[] = {{\n")

        for addr, name in bb_table.items():
            file.write(f"    {{0x{addr:08X}, &{name}}},\n")

        file.write(f"    {{0, NULL}},\n")
        file.write("};\n")

    # Build program info table
    with open(basedir / "info.c", "wt") as file:
        file.write('#include "AsmC-x86-32.h"\n\n')
        file.write(f"const AsmC_ProgramInfo32_t {MODULE}_info = {{\n")
        file.write(f"    0x{ENTRY_POINT:08X},    /* address entry point */\n")
        file.write("};\n")

    # with open(basedir / "program.h", "wt") as file:
    #     pass
