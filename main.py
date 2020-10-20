"""
usage: main.py inputs/Heroes3.exe Heroes3.output

- first we dump some generic info
- then we dump the entirety of .text without any symbol resolution
- then ???
"""
import time

import pefile
import pickle

import sys

import chunkutils
import data_io
from AsmProj import asmproj
import projectutils
from analysis import try_make_code_chunk
from chunkutils import cluster_chunks, calculate_code_coverage
from data import *
from data import AnalysisState
from drawtable import Table
from peutils import generate_image_map


def the_loop(INPUT_PATH, OUTPUT_PATH):
    MAKE_PE_STRUCTURE = True
    MAKE_MAP = True

    # create output directories
    for dir in {OUTPUT_PATH}:
        dir.mkdir(parents=True, exist_ok=True)

    pe =  pefile.PE(INPUT_PATH)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_point = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # generate image map

    if MAKE_MAP:
        with open(OUTPUT_PATH / "info-pe-map.txt", "wt") as f:
            print(f"image_base=0x{image_base:08x}", file=f)
            generate_image_map(pe, file=f)

    if MAKE_PE_STRUCTURE:
        with open(OUTPUT_PATH / 'info-pe-headers.txt', 'wt') as f:
            t = Table([("name", 10, "%10s"),
                       ("va(rel)", 10, "0x%08x"),
                       ("va(abs)", 10, "0x%08x"),
                       ("vsize", 10, "0x%08x"),
                       ("size", 10, "0x%08x"),
                      ], file=f)

            for section in pe.sections:
                name = section.Name.decode(errors="ignore")
                t.row(name, section.VirtualAddress, pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
                      section.Misc_VirtualSize, section.SizeOfRawData)

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print('DIRECTORY_ENTRY_IMPORT', entry.dll.decode(), file=f)
                for imp in entry.imports:
                    print('\t', hex(imp.address), imp.name.decode() if imp.name else "??", file=f)

            #for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            #    print('DIRECTORY_ENTRY_EXPORT', hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal, file=f)

            print(pe.dump_info(), file=f)

    def find_section_in_pefile(pe: pefile.PE, name) -> pefile.SectionStructure:
        for section in pe.sections:
            if section.Name.startswith(name):
                return section

        raise Exception("No such section: " + str(name))

    # init labels database
    try:
        labels_db = data_io.load_labels(OUTPUT_PATH)
        print("Resuming with", OUTPUT_PATH / "labels")
    except FileNotFoundError:
        labels_db = {}
        labels_db[entry_point] = Label(f"entry_{entry_point:06x}", entry_point, origin="header")

        def sanitize_label(s):
            return s.replace("@", "_").replace("?", "_")

        # load imports
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # print('DIRECTORY_ENTRY_IMPORT', entry.dll.decode(), file=f)
            for imp in entry.imports:
                # print('\t', hex(imp.address), imp.name.decode(), file=f)

                labels_db[imp.address] = Label("__imp_" + sanitize_label(imp.name.decode() if imp.name else f"unk{imp.address:08X}"), imp.address, origin="import")

        # load exports
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            addr = pe.OPTIONAL_HEADER.ImageBase + exp.address
            labels_db[addr] = Label(sanitize_label(exp.name.decode() if exp.name else f"unk{addr:08X}"), addr, origin="export")


        #print("ENTRY %08x" % (image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint,))
        # print(labels_db)

    try:
        code_chunks = data_io.load_chunks(OUTPUT_PATH)
        print("Resuming with", OUTPUT_PATH / "chunks")
    except FileNotFoundError:
        code_chunks = []

        for section in pe.sections:
            raw_data = section.get_data() #pe.get_memory_mapped_image()[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
            assert len(raw_data) == section.SizeOfRawData

            section_name = section.Name.rstrip(b'\x00').decode()

            if section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_CNT_CODE"]:
                chunk_type = UnknownChunk
            else:
                chunk_type = RawChunk

            chunk = chunk_type(section_name,
                               image_base + section.VirtualAddress,
                               image_base + section.VirtualAddress + len(raw_data),
                               raw_data)
            code_chunks.append(chunk)

            if section.Misc_VirtualSize > section.SizeOfRawData:
                if section_name == ".data":
                    # special handling of .bss, at least until we are generating our own linker scripts
                    chunk = RawChunk(".bss",
                                     image_base + section.VirtualAddress + len(raw_data),
                                     image_base + section.VirtualAddress + section.Misc_VirtualSize,
                                     bytearray(section.Misc_VirtualSize - len(raw_data)))
                    code_chunks.append(chunk)
                else:
                    # add padding directly into chunk
                    chunk.end = image_base + section.Misc_VirtualSize
                    chunk.bytes += bytearray(section.Misc_VirtualSize - len(raw_data))

        # create initial set of chunks from executable sections
        # dot_text = find_section_in_pefile(pe, b".text")
        # text = pe.get_memory_mapped_image()[dot_text.PointerToRawData:dot_text.PointerToRawData + dot_text.SizeOfRawData]
        #
        # dot_rdata = find_section_in_pefile(pe, b".rdata")
        # rdata = pe.get_memory_mapped_image()[dot_rdata.PointerToRawData:dot_rdata.PointerToRawData + dot_rdata.SizeOfRawData]
        #
        # code_chunks = [
        #     UnknownChunk(".text", image_base + dot_text.VirtualAddress, image_base + dot_text.VirtualAddress + len(text), text),
        #     RawChunk(".rdata", image_base + dot_rdata.VirtualAddress, image_base + dot_rdata.VirtualAddress + len(rdata), rdata),
        # ]
        #
        # try:
        #     dot_data = find_section_in_pefile(pe, b".data")
        #     data = pe.get_memory_mapped_image()[dot_data.PointerToRawData:dot_data.PointerToRawData + dot_data.SizeOfRawData]
        #
        #     # for now, make sure an assembly source is generated for .bss as well
        #     # later on, we will split .data and .bss and inject symbols through linker script
        #     bss_len = max(dot_data.Misc_VirtualSize - dot_data.SizeOfRawData, 0)
        #     bss_data = bytearray(bss_len)
        #
        #     code_chunks += [
        #         RawChunk(".data", image_base + dot_data.VirtualAddress, image_base + dot_data.VirtualAddress + len(data), data),
        #         RawChunk(".bss", image_base + dot_data.VirtualAddress + len(data), image_base + dot_data.VirtualAddress + len(data) + bss_len, bss_data),
        #     ]
        # except:     # FIXME: catch specific exception type
        #     pass

        # detect chunks of valid code
        # print("DO analysis:detect_chunks")
        #code_chunks = detect_chunks(image_base, dot_text.VirtualAddress, text)

    try:
        disassembler_db = data_io.load_disassembler_db(OUTPUT_PATH / "disassembler-db")
    except FileNotFoundError:
        disassembler_db = DisassemblerDb()

    log_file = open(OUTPUT_PATH / "log-builds.html", "at")
    if log_file.tell() == 0:
        print('<style>body, td, th { font-family: "Roboto", sans-serif; font-size: 10pt } td, th { padding: 4px 8px; text-align: right }</style>', file=log_file)
        print("<table border='1'>", file=log_file)
        print("<tr><th>pass</th><th>seeds processed</th><th>seeds in back-log</th><th>code coverage</th><th>build successful?</th><th>build time</th></tr>", file=log_file)

    def split_up_chunks(code_chunks, labels_db):
        sorted_labels_db: List[Label] = sorted(labels_db.values(), reverse=True)

        new_code_chunks = []
        reanalyze_code_seeds = []

        for chunk in code_chunks:
            if True: #isinstance(chunk, CodeChunk):
                # eat all labels in this chunk and split if function
                while len(sorted_labels_db):
                    # end of sorted_labels_db == label with lower address
                    if sorted_labels_db[-1].address >= chunk.end:
                        # no more labels for this chunk
                        break

                    # pop label with lowest address
                    label = sorted_labels_db.pop()

                    if label.address < chunk.start:
                        # belongs to previous chunk, which must have not been CodeChunk
                        print(f"Error: skipped label {label} when entering {chunk}")
                    elif label.address == chunk.start:
                        # all ok, nothing to do
                        pass
                    elif label.address > chunk.start and label.address < chunk.end:
                        if True: # label.name.startswith("func_"):
                            # TODO: this is extremely redundant with get_or_split_chunk_at. merge!
                            new_chunk_type = UnknownChunk
                            new_chunk_1 = new_chunk_type(chunk.section_name, chunk.start, label.address, chunk.bytes[:label.address - chunk.start])
                            new_chunk_2 = new_chunk_type(chunk.section_name, label.address, chunk.end, chunk.bytes[label.address - chunk.start:])

                            if isinstance(chunk, BasicBlock):
                                reanalyze_code_seeds.append(new_chunk_1.start)

                            new_code_chunks.append(new_chunk_1)
                            chunk = new_chunk_2

            new_code_chunks.append(chunk)

        return new_code_chunks, reanalyze_code_seeds

    try:
        with open(OUTPUT_PATH / "analysis_state.pickle", "rb") as f:
            an = pickle.load(f)
    except FileNotFoundError:
        initial_seeds = {entry_point}

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            addr = pe.OPTIONAL_HEADER.ImageBase + exp.address
            # stay vigilant -- for the same address may be exported multiple times!
            initial_seeds.add(addr)

        an = AnalysisState(pass_=1,
                           pending_rebuild=True,
                           pending_seeds=list(initial_seeds),
                           seeds=set(initial_seeds),
                           seeds_processed_total=0,
                           )

    # loop for as long as we are getting new information
    while True:
        print()
        print(f"REcycler loop pass {an.pass_} ({an.seeds_processed_total} seeds processed so far, {len(an.pending_seeds)} seeds in back-log)")
        print()

        build_result = None

        if an.pending_rebuild:
            # try to disassemble & rebuild
            an.pending_rebuild = False

            begin = time.time()

            print(f"Clustering {len(code_chunks)} chunks for disassembly...")
            clusters = cluster_chunks(code_chunks, cluster_size_bytes=64 * 1024, labels_db=labels_db)

            with open(OUTPUT_PATH / "info-clusters.txt", "wt") as f:
                for cluster in clusters:
                    print(f" -- CLUSTER {cluster}", file=f)

                    for chunk in cluster.chunks:
                        print(chunk, file=f)

            data_io.save_clusters(OUTPUT_PATH / "tmp-clusters", clusters)
            data_io.save_labels(OUTPUT_PATH, labels_db, suffix=".tmp")

            project = asmproj.disassemble_and_make_project(INPUT_PATH, OUTPUT_PATH, disassembler_db)
            build_result = projectutils.build_project(project, disassembler_db)

            end = time.time()

            coverage = calculate_code_coverage(code_chunks, ".text")

            print(f"<tr><td>{an.pass_}</td><td>{an.seeds_processed_total}</td><td>{len(an.pending_seeds)}</td><td>{coverage * 100:.2f} %</td>" +
                  f"<td>{build_result.success if build_result else None}</td><td>{end - begin:.1f} sec</td></tr>", file=log_file)
            log_file.flush()

            if build_result.new_information:
                an.pending_rebuild = True
                data_io.save_disassembler_db(OUTPUT_PATH / "disassembler-db", disassembler_db)

                with open(OUTPUT_PATH / "info-disassembler-db.txt", "wt") as f:
                    disassembler_db.dump(f)

            if build_result.success:
                # save "last-good" program database
                print(f"Build successful ({coverage * 100:.2f}% coverage), saving results")
                data_io.save_chunks(OUTPUT_PATH, code_chunks, suffix=".good")
                data_io.save_labels(OUTPUT_PATH, labels_db, suffix=".good")
            elif not build_result.new_information:
                raise Exception("Build failed, and we didn't learn anything new")

        # If there are no build issues, we try to proceed with discovering more code

        analysis_seeds_processed_this_time = 0

        while (build_result is None or build_result.success) and len(an.pending_seeds) and analysis_seeds_processed_this_time < 1000:
            seed = an.pending_seeds.pop(0)

            if seed < image_base:
                print(f"Skip seed {seed:08X}h (outside executable)")
                break

            print(f"Analyze chunk @ seed {seed:08X}h")
            code_chunks, chunk, i, reanalyze_code_seed = chunkutils.get_or_split_chunk_at(code_chunks, seed)

            code_chunk, rest_chunk = try_make_code_chunk(chunk, labels_db=labels_db, pe=pe)

            if code_chunk:
                if len(code_chunk.code_refs):
                    print(f"    -> code xrefs", *[f"{ref:08X}h" for ref in code_chunk.code_refs])

                for code_ref in code_chunk.code_refs:
                    if code_ref not in an.seeds:
                        an.pending_seeds.append(code_ref)
                        an.seeds.add(code_ref)

                an.pending_rebuild = True

            # splice new chunks into list
            code_chunks = code_chunks[:i] + ([code_chunk] if code_chunk else []) + ([rest_chunk] if rest_chunk else []) + code_chunks[i + 1:]

            if reanalyze_code_seed is not None:
                print(f"Note: need to re-analyze chunk @ seed {reanalyze_code_seed:08X}h")
                if reanalyze_code_seed not in an.pending_seeds:
                    an.pending_seeds.append(reanalyze_code_seed)

            an.seeds_processed_total += 1
            analysis_seeds_processed_this_time += 1

        # if there could have been new labels introduced, ensure chunks are split properly
        # (doing it here like this might not be the best solution)
        if analysis_seeds_processed_this_time > 0:
            print(f"Splitting up {len(code_chunks)} chunks at labels...")
            code_chunks, reanalyze_code_seeds = split_up_chunks(code_chunks, labels_db)

            for seed in reanalyze_code_seeds:
                print(f"Note: need to re-analyze chunk @ seed {seed:08X}h")
                if seed not in an.pending_seeds:
                    an.pending_seeds.append(seed)

        # rename what looks functions labels, etc.
        # TODO: do this in a more targeted way
        for label in labels_db.values():
            if label.origin != "code":
                continue

            if label.usages["call"] > 0 or Label.FLAG_FUNCTION_PROLOGUE in label.flags:
                label.name = f"func_{label.address:06x}"
            elif label.usages["jump"] > 0:
                label.name = f"l_{label.address:06x}"

        with open(OUTPUT_PATH / "analysis_state.pickle", "wb") as f:
            pickle.dump(an, f)
        data_io.save_chunks(OUTPUT_PATH, code_chunks)
        data_io.save_labels(OUTPUT_PATH, labels_db)

        # Print out labels

        with open(OUTPUT_PATH / "info-labels.txt", 'wt') as f:
            t = Table([("name", 40, "%-s"),
                       ("origin", 10, "%s"),
                       ("va(abs)", 10, "0x%08x"),
                       ("usages", 80, "%s"),
                       ("flags", 20, "%s"),
                       ], file=f)

            for _, label in sorted(labels_db.items()):
                t.row(label.name, label.origin, label.address, label.usages, label.flags)

        if not an.pending_rebuild and not len(an.pending_seeds):
            break
        else:
            an.pass_ += 1

    log_file.close()

    print("Nothing else to do!")
    return

    # code_chunks = fixup_chunks(code_chunks)
    #
    # # analyze code section and detect references
    # print("DO analysis:detect_labels")
    # detect_labels(pe, code_chunks, labels_db)
    #
    # # look for function prologues
    # print("DO analysis:detect_function_prologues")
    # detect_function_prologues(code_chunks, labels_db)
    #
    # unreferenced_function_prologues = []
    # for label in labels_db.values():
    #     if Label.FLAG_FUNCTION_PROLOGUE in label.flags and label.usages["call"] == 0:
    #         unreferenced_function_prologues.append(label)
    #
    # print(f"{len(unreferenced_function_prologues)} unreferenced_function_prologues:", " ".join([str(l) for l in unreferenced_function_prologues]))

if __name__ == "__main__":
    INPUT_PATH, OUTPUT_PATH = Path(sys.argv[1]), Path(sys.argv[2])

    the_loop(INPUT_PATH, OUTPUT_PATH)
