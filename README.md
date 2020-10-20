## How to use

Create a virtual env:

    python3 -m virtualenv venv
    . venv/bin/activate

Run:

    python main.py inputs/MyExecutable.exe MyExecutable.project

### Supported platforms & binary formats

- Only Win32/x86/PE for the moment

### Dependencies

 - _binutils_ for the target platform (e.g. from the MinGW project)
 - _diff_, _make_
 - _python3_

On a Linux system, all of these should be readily available. Run with `PREFIX=i686-w64-mingw32-` in the environment.

On Windows, it is recommended to:
 - install [MSYS2](https://www.msys2.org/) and native Python 3
 - do `pacman -S diffutils mingw-w64-i686-binutils`
 - you'll need to add a bunch of directories to your PATH when running REcycler, for example `C:\usr\msys64\usr\bin\;C:\usr\msys64\mingw32\bin`

Another option, of course, is to use WSL.

## Notes about operators

### make_imported_labels

Generate labels for imported functions.

- Input: Exe
- Output: Set[Label]

### detect_chunks

Detect spans of disassemble-able code.

- Input: Exe
- Output: List[Chunk]

### detect_labels

Infer labels from instruction targets (data access, jumps etc.)

- Input: Exe.SectionMap
- Input: List[Chunk]
- Output: Set[Label]

### detect_function_prologues

Infer labels from function prologues

- Input: List[Chunk]
- Output: Set[Label]

### split_up_chunks

Split chunks at function boundaries.

- Input: List[Chunk]
- Input: Set[Label]
- Output: List[Chunk] 

### cluster_chunks

- Input: List[Chunk]
- Input: option cluster_size_bytes
- Output: List[List[Chunk]]

### disassemble_clusters

- Input: List[List[Chunk]]
- Input: Set[Label]
- Output: List[AsmSource, VMA, Length]

### generate_project

- Input: path to Exe
- Input: List[AsmSource, VMA, Length]
- Output: GasProject

## Directory structure

    <project>.project/
        build/
        gen-asm/
