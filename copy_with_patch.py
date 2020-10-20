#!/usr/bin/env python3

import os
import sys

input_path, output_path, offset, patch_path = sys.argv[1:]

with open(input_path, "rb") as input, open(patch_path, "rb") as patch, open(output_path, "wb") as output:
    in_block = input.read(int(offset, 0))
    output.write(in_block)
    del in_block

    patch_data = patch.read()
    output.write(patch_data)
    input.seek(len(patch_data), os.SEEK_CUR)
    del patch_data

    in_rest = input.read()
    output.write(in_rest)
    del in_rest
