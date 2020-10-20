import sys
from pathlib import Path

from data import BasicBlock
import data_io
from . import generate_AsmC

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("project", type=Path)
args = parser.parse_args()

chunks = data_io.load_chunks(args.project)
basic_blocks = [chunk for chunk in chunks if isinstance(chunk, BasicBlock)]

generate_AsmC(basic_blocks, args.project)
