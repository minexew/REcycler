def generate_image_map(pe, file):
    ranges = []

    ranges += [(0, pe.OPTIONAL_HEADER.SizeOfHeaders, "PE headers", pe)]

    for section in pe.sections:
        ranges += [
            (
                section.PointerToRawData,
                section.SizeOfRawData,
                "section " + section.Name.decode(),
                section,
            )
        ]

    ranges.sort(key=lambda range: range[0])

    last_end = 0
    for range in ranges:
        start, length, name, ref = range
        if start > last_end:
            print(
                f"{last_end:08X}h .. {start:08X}h\t{start - last_end:08X}h\t{start - last_end}\tUNKNOWN",
                file=file,
            )
        print(
            f"{start:08X}h .. {start + length:08X}h\t{length:08X}h\t{length}\t{name}",
            file=file,
        )
        last_end = start + length

    start = pe.OPTIONAL_HEADER.SizeOfImage
    if start > last_end:
        print(
            f"{last_end:08X}h .. {start:08X}h\t{start - last_end:08X}h\t{start - last_end}\tUNKNOWN",
            file=file,
        )
