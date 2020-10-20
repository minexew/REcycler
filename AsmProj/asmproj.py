import pefile
from copy import deepcopy
from pathlib import Path, PurePosixPath

import sys

import analysis
import data_io
from . import disassembly_gas
from asmutils import gnuas_escape_label
from data import Project, DisassemblerDb

AS = "gas"
MIN_OFFSET = 0


def disassemble_and_make_project(INPUT_PATH, project_dir: Path, disassembler_db: DisassemblerDb):
    build_dir = project_dir / "build"
    gen_asm_dir = project_dir / "gen-asm"

    # create output directories
    # TODO: gen_asm_dir should be emptied, since cluster boundaries can change between runs
    for dir in {project_dir, build_dir, gen_asm_dir}:
        dir.mkdir(parents=True, exist_ok=True)

    prj = Project(INPUT_PATH, project_dir, disassembler_db_snapshot=deepcopy(disassembler_db))

    pe =  pefile.PE(INPUT_PATH)
    exe_patch_offset = pe.sections[0].PointerToRawData

    clusters = data_io.load_clusters(project_dir / "tmp-clusters")
    labels_db = data_io.load_labels(project_dir, suffix=".tmp")

    print(f"Disassembling {len(clusters)} clusters...")

    for cluster in clusters:
        filename = gen_asm_dir / f"{cluster.section_name[1:]}_{cluster.start:08X}.s"
        print(f" - {filename} : {len(cluster.chunks)} chunks")

        if cluster.start < MIN_OFFSET:
            continue

        total_length = sum([len(chunk.bytes) for chunk in cluster.chunks])
        cluster_end = cluster.start + total_length

        with open(filename, 'wt') as f:
            if AS == "gas":
                print(f"""\
.intel_syntax
.section {cluster.section_name}
""", file=f)

                # export labels
                for label in sorted(labels_db.values()):
                    if label.address >= cluster_end:
                        break
                    elif label.address >= cluster.start:
                        print(f".global {gnuas_escape_label(label.name):40s} /* {label} */", file=f)

                print(file=f)
                disassembly_gas.disassemble_for_GAS(cluster.chunks, f, disassembler_db=disassembler_db, labels_db=labels_db, use_labels=True)

            if AS == "nasm":
                print(f"""\
section {cluster.section_name}
""", file=f)

                analysis.disassemble_for_nasm(cluster.chunks, f, labels_db=labels_db, use_labels=True)

        prj.add_asm_source(filename, cluster.start, total_length)

    # Generate MinGW project

    def relpath(path_to, path_from):
        path_to = Path(path_to).resolve()
        path_from = Path(path_from).resolve()
        try:
            for p in (*reversed(path_from.parents), path_from):
                head, tail = p, path_to.relative_to(p)
        except ValueError:  # Stop when the paths diverge.
            pass
        return Path('../' * (len(path_from.parents) - len(head.parents))).joinpath(tail)

    def generate_project(prj: Project):
        # generate project Makefile

        project_makefile = project_dir / "Makefile"

        P = PurePosixPath
        makefile_cwd = project_dir
        # relative_source_dir = Path().relative_to(self.output_dir)

        build_dir_rel = relpath(build_dir, makefile_cwd)

        input_exe_path = relpath(prj.exe_path, makefile_cwd)
        prj.output_path = relpath(project_dir / prj.exe_path.name, makefile_cwd)
        ldscript = relpath("i386pe.x", makefile_cwd)

        with open(project_makefile, "wt", newline='\n') as f:
            all_obj = []

            for src in prj.sources:
                obj_path = relpath(build_dir / src.path.stem, makefile_cwd).with_suffix(".o")
                all_obj.append(obj_path)

            # link objects
            obj_paths = " ".join([str(P(obj_path)) for obj_path in all_obj])

            # FIXME: un-hardcode!
            text_start = 0x10001000

            print(f"""
#PREFIX=i686-w64-mingw32-
AS=$(PREFIX)as
LD=$(PREFIX)ld
OBJCOPY=$(PREFIX)objcopy
OBJDUMP=$(PREFIX)objdump

ALLCODE_BIN={P(build_dir_rel)}/allcode.bin
ALLCODE_O={P(build_dir_rel)}/allcode.o
ALLCODE_S={P(build_dir_rel)}/allcode.s
OUTPUT_EXE={P(prj.output_path)}
OUTPUT_S={P(build_dir_rel)}/output.s
COPY_WITH_PATCH={P(relpath("copy_with_patch.py", project_dir))}

all: input.s $(OUTPUT_EXE) $(OUTPUT_S)

input.s: {P(input_exe_path)}
\t$(OBJDUMP) -M intel -D -h $< | tail -n +3 >$@

$(ALLCODE_O): {obj_paths} {P(ldscript)}
\tar rcs {P(build_dir_rel)}/allcode.a {obj_paths}
\t$(LD) -T  {P(ldscript)} -Ttext=0x{text_start:08x} {obj_paths} -o $@
\t$(OBJDUMP) -M intel -D -h $(ALLCODE_O) >$(ALLCODE_S)

$(ALLCODE_BIN): $(ALLCODE_O)
\t$(OBJCOPY) --only-section=.text -O binary $< $@

$(OUTPUT_EXE): $(ALLCODE_BIN) {P(input_exe_path)}
\t$(COPY_WITH_PATCH) {P(input_exe_path)} $@ {exe_patch_offset} $(ALLCODE_BIN)
\t#cp {P(input_exe_path)} $@
\t#dd if=$(ALLCODE_BIN) of=$@ obs=1 seek={exe_patch_offset} conv=notrunc 2>&1

$(OUTPUT_S): $(OUTPUT_EXE)
\t$(OBJDUMP) -M intel -D -h $< | tail -n +3 >$@

""", file=f)

            for src in prj.sources:
                src_path = relpath(src.path, makefile_cwd)
                obj_path = relpath(build_dir / src.path.stem, makefile_cwd).with_suffix(".o")     # TODO DRY

                print(f"{P(obj_path)}: {P(src_path)}", file=f)
                if AS == "gas":
                    print(f"\t$(AS) $< -o $@", file=f)
                print(file=f)

            # all_obj = []
            #
            # for src in prj.sources:
            #     if src.offset < MIN_OFFSET: continue
            #
            #     # patch_offset = src.offset + prj.text_vma_to_file_offset
            #     # print(f"makeproject: {src.path} @ {src.offset:08X}h")
            #
            #     # strategy: compile asm source to .o, export as flat binary, patch exe file (diff in the end)
            #     src_path = relpath(src.path, makefile_cwd)
            #     obj1_path = relpath(prj.output_dir / (src.path.stem + "a"), makefile_cwd).with_suffix(".o")
            #     obj_path = relpath(prj.output_dir / src.path.stem, makefile_cwd).with_suffix(".o")
            #     dasm_path = relpath(prj.output_dir / src.path.stem, makefile_cwd).with_suffix(".s")
            #     bin_path = relpath(prj.output_dir / src.path.stem, makefile_cwd).with_suffix(".bin")
            #
            #     # print(f"# cluster {src.offset:08X}h: {src.length:6} bytes @ {patch_offset:X}h", file=f)
            #
            #     if AS == "nasm":
            #         print(f"nasm {P(src_path)} -f elf32 -o {P(obj_path)}", file=f)
            #     #print(f"$LD -Ttext=0x{src.offset:08X} {P(obj1_path)} -o {P(obj_path)}", file=f)
            #     # print(f"$OBJDUMP -M intel -D {P(obj_path)} >{P(dasm_path)}", file=f)
            #     # print(f"$OBJCOPY --only-section=.text -O binary {P(obj_path)} {P(bin_path)}", file=f)
            #     # print(f"dd if={P(bin_path)} of={P(prj.output_path)} obs=1 seek={patch_offset} conv=notrunc", file=f)
            #
            #     print(file=f)
            #
            #     all_obj.append(obj_path)

                #break

    #         print(f"""
    # # post-diff
    # cmp -l {P(input_exe_path)} {P(prj.output_path)} | gawk '{{printf "%08X %02X %02X\\n", $1, strtonum(0$2), strtonum(0$3)}}'
    # """, file=f)

            # generate linker script

            # ndisasm bigobj & compare
            # print(f"ndisasm bigobj.bin -b 32 -o 0x401000 >bigobj.asm", file=f)

    generate_project(prj)

    return prj
