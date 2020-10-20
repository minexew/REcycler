from typing import List, Optional

from data import ChunkCluster, Label, Chunk, UnknownChunk, BasicBlock


def cluster_chunks(chunks, cluster_size_bytes, labels_db):
    clusters = []

    last_chunk_section = chunks[0].section_name
    last_chunk_end = chunks[0].start

    cluster = ChunkCluster(chunks[0].section_name, chunks[0].start, [])

    for chunk in chunks:
        # assert no gaps between chunks
        if chunk.section_name == last_chunk_section and chunk.start != last_chunk_end:
            print(f"Error: gap between chunks {last_chunk_end:08X}h..{chunk}")
            assert chunk.start == last_chunk_end

        # have we crossed into the next "page"?
        if (chunk.start // cluster_size_bytes > cluster.start // cluster_size_bytes
                and chunk.start in labels_db
                # only split on a function boundary to not break short relative jump
                # TODO: in non-code sections, split on any label
                and Label.FLAG_FUNCTION_PROLOGUE in labels_db[chunk.start].flags
                # ld seems to impose 4-byte padding between objects, so we need to be extra careful not to get bit
                and chunk.start % 4 == 0):
            clusters.append(cluster)

            cluster = ChunkCluster(chunk.section_name, chunk.start, [])

        # crossed into another section?
        if chunk.section_name != cluster.section_name:
            if len(cluster.chunks):
                clusters.append(cluster)

            cluster = ChunkCluster(chunk.section_name, chunk.start, [])

        cluster.chunks.append(chunk)

        last_chunk_end = chunk.end

    if len(cluster.chunks):
        clusters.append(cluster)

    return clusters


def get_or_split_chunk_at(code_chunks: List[Chunk], address_vma: int) -> (List[Chunk], Chunk, int, Optional[int]):
    for i, chunk in enumerate(code_chunks):
        if address_vma == chunk.start:
            # perfect!
            return code_chunks, chunk, i, None
        elif address_vma > chunk.start and address_vma < chunk.end:
            # oh no! gotta split the chunk
            #assert isinstance(chunk, UnknownChunk)

            new_chunk_type = UnknownChunk
            new_chunk_1 = new_chunk_type(chunk.section_name, chunk.start, address_vma, chunk.bytes[:address_vma - chunk.start])
            new_chunk_2 = new_chunk_type(chunk.section_name, address_vma, chunk.end, chunk.bytes[address_vma - chunk.start:])

            if isinstance(chunk, BasicBlock):
                reanalyze_code_seed = new_chunk_1.start
            else:
                reanalyze_code_seed = None

            code_chunks = code_chunks[:i] + [new_chunk_1, new_chunk_2] + code_chunks[i + 1:]
            return code_chunks, new_chunk_2, i + 1, reanalyze_code_seed

    raise Exception("Out of executable!")


def calculate_code_coverage(code_chunks, section_name):
    text_covered = 0
    text_total = 0

    for chunk in code_chunks:
        if chunk.section_name != section_name:
            continue

        if isinstance(chunk, BasicBlock):
            text_covered += len(chunk.bytes)

        text_total += len(chunk.bytes)

    return text_covered / text_total