import pickle
from pathlib import Path
from typing import Iterable

from data import ChunkCluster, DisassemblerDb, Chunk


def load_chunks(projectpath: Path) -> Iterable[Chunk]:
    with open(projectpath / "chunks.pickle", "rb") as f:
        return pickle.load(f)


def load_clusters(path: Path) -> Iterable[ChunkCluster]:
    with open(path.with_suffix(".pickle"), "rb") as f:
        return pickle.load(f)


def load_disassembler_db(path: Path) -> DisassemblerDb:
    with open(path.with_suffix(".pickle"), "rb") as f:
        return pickle.load(f)


def load_labels(projectpath: Path, suffix="") -> dict:
    with open(projectpath / ("labels.pickle" + suffix), "rb") as f:
        return pickle.load(f)


def save_chunks(projectpath: Path, chunks: Iterable[Chunk], suffix=""):
    with open(projectpath / ("chunks.pickle" + suffix), "wb") as f:
        pickle.dump(chunks, f)


def save_clusters(path: Path, clusters: Iterable[ChunkCluster]):
    with open(path.with_suffix(".pickle"), "wb") as f:
        pickle.dump(clusters, f)


def save_disassembler_db(path: Path, disassembler_db: DisassemblerDb):
    with open(path.with_suffix(".pickle"), "wb") as f:
        pickle.dump(disassembler_db, f)


def save_labels(projectpath: Path, labels: dict, suffix=""):
    with open(projectpath / ("labels.pickle" + suffix), "wb") as f:
        pickle.dump(labels, f)
