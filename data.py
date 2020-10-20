from dataclasses import dataclass, field

from enum import auto, Enum
from functools import total_ordering
from pathlib import Path
from typing import List, Any, Iterable, Set


class CpuArch(Enum):
    CPU_X86_32 = auto()


@dataclass
class Chunk:
    section_name: str
    start: int
    end: int
    bytes: bytes

    def __post_init__(self):
        assert self.end > self.start
        assert self.end - self.start == len(self.bytes)

    def __repr__(self):
        return f"({self.__class__.__name__} {self.section_name} {self.start:08X}h..{self.end:08X}h, {len(self.bytes)} bytes)"


@dataclass
class BasicBlock(Chunk):
    arch: CpuArch
    code_refs: Iterable[int]
    data_refs: Iterable[int]

    # def __init__(self, section_name, start, end, bytes, code_refs, data_refs):
    #     super(CodeChunk, self).__init__(section_name, start, end, bytes)
    #     self.code_refs

    def __repr__(self):
        return super(BasicBlock, self).__repr__()


class RawChunk(Chunk):
    pass


class UnknownChunk(Chunk):
    pass


@dataclass
class ChunkCluster(object):
    section_name: str
    start: int
    chunks: []

    def __repr__(self):
        return f"(ChunkCluster {self.section_name} {self.start:08X}h.., {len(self.chunks)} chunks)"


@total_ordering
class Label:
    FLAG_FUNCTION_PROLOGUE = "function_prologue"

    def __init__(self, name, address, origin):
        self.name = name
        self.address = address  # VMA
        self.origin = origin

        self.flags = set()
        self.usages = dict(call=0, data1=0, data2=0, data4=0, data8=0, imm=0, jump=0)

    def __lt__(self, other):
        assert isinstance(other, Label)

        return self.address < other.address

    def __repr__(self):
        return f"({self.name} 0x{self.address:08x})"


class DisassemblerDb(object):
    def __init__(self):
        # dict keyed by first byte. value = dict keyed by byte string
        self.alternative_encoding_buckets = dict()

    def dump(self, f):
        for first_byte, bucket in self.alternative_encoding_buckets.items():
            bytes_: bytes
            for bytes_, (value, origin_vma, mnemonic, operands) in bucket.items():
                print(f"{origin_vma:08X}h {bytes_.hex():16s} {mnemonic:8s} {operands:20s} {value}", file=f)

    def has_alternative_encoding_entry(self, mnemonic, operands, bytes):
        first_byte = bytes[0]

        try:
            bucket = self.alternative_encoding_buckets[first_byte]

            return bytes in bucket
        except KeyError:
            return False

    def set_alternative_encoding_entry(self, mnemonic, operands, bytes, origin_vma, value):
        first_byte = bytes[0]

        try:
            bucket = self.alternative_encoding_buckets[first_byte]
        except KeyError:
            bucket = dict()
            self.alternative_encoding_buckets[first_byte] = bucket

        bucket[bytes] = (value, origin_vma, mnemonic, operands)

    def try_get_alternative_encoding_entry(self, bytes):
        first_byte = bytes[0]

        try:
            bucket = self.alternative_encoding_buckets[first_byte]
            value, origin_vma, mnemonic, operands = bucket[bytes]
            return value
        except KeyError:
            return None


@dataclass
class ProjectSource:
    path: Path
    offset: int
    length: int  # length of assembled code, in bytes


@dataclass
class Project:
    exe_path: Path  # input executable. if project is not 100% complete, this will be used to fill in gaps
    dir: Path
    #text_vma_to_file_offset: int
    disassembler_db_snapshot: DisassemblerDb

    sources: List[ProjectSource] = field(default_factory=list)

    def add_asm_source(self, path, offset_address, length):
        self.sources.append(
            ProjectSource(path=path, offset=offset_address, length=length)
        )


@dataclass
class ProjectBuildResult(object):
    success: bool
    new_information: bool


class AlternativeEncodingEntry(Enum):
    ALTERNATIVE_ENCODING_ACTIVE = 1
    ALTERNATIVE_ENCODING_FAILED = 2
    X86_JUMP_REL32 = 3


@dataclass
class AnalysisState:
    pass_: int
    pending_rebuild: bool
    pending_seeds: List[int]

    seeds: Set[int]
    seeds_processed_total: int