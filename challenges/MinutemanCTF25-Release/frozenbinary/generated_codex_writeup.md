# Frozen binary - Reversing Writeup (Codex)

## Goal
Recover the flag from a binary that skips its flag generation via an inline `jmp`.

## High-level Observation
The provided `flag.c` shows a deliberate jump in `main`:

```c
asm("jmp .+7"); // Darn you ice king!
result = generate_flag();
```

This short jump skips the call to `generate_flag()`, so the binary always prints
`"No flag for you!"`. Removing that jump restores normal execution.

## Core Insight
The `jmp` is a 2-byte short jump (`eb 05`) in `main`. Patching it to `nop nop`
forces the program to fall through into the `generate_flag()` call.

## Patch Strategy
1. Locate the byte sequence around the jump in the binary.
2. Replace `eb 05` with `90 90`.
3. Execute the patched binary to print the flag.

In this build, the pattern:
```
48 89 45 f8 eb 05 e8
```
appears once in `main`. The `eb 05` bytes are replaced.

## Generated Solver (Full)
Saved as `generated_solve.py` in this folder.

```py
import os
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path


def ensure_binary(root: Path) -> Path:
    binary = root / "static" / "binary"
    if binary.exists():
        return binary

    zip_path = root / "static" / "frozenbinary.zip"
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(root / "static")
    if not binary.exists():
        raise FileNotFoundError("binary not found after extraction")
    return binary


def patch_binary(data: bytes) -> bytes:
    pattern = b"\x48\x89\x45\xf8\xeb\x05\xe8"
    idx = data.find(pattern)
    if idx == -1:
        raise ValueError("jump pattern not found")

    patch_at = idx + 4
    return data[:patch_at] + b"\x90\x90" + data[patch_at + 2 :]


def main() -> None:
    root = Path(__file__).resolve().parent
    binary = ensure_binary(root)

    data = binary.read_bytes()
    patched = patch_binary(data)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(patched)
        tmp_path = Path(tmp.name)

    os.chmod(tmp_path, os.stat(tmp_path).st_mode | stat.S_IXUSR)
    result = subprocess.check_output([str(tmp_path)])
    print(result.decode(errors="ignore").strip())


if __name__ == "__main__":
    main()
```

## Docker Validation
Executed in a clean container to verify the generated solver:

```bash
./verify.sh
```

Output:

```
OK: generated_solve.py
All verification checks passed.
```

## Reproducible Verification
Included for collaborators:
- `Dockerfile.verify` provides a minimal Python environment.
- `verify.sh` runs the generated solver and checks for the expected flag.

## Writeup Process (Reusable)
Use this sequence for future challenges to keep writeups reproducible:

1. Collect the challenge files, official solve script, and any existing writeups.
2. Reverse the binary and summarize the core insight.
3. Create a standalone `generated_solve.py` that prints the flag deterministically.
4. Add `Dockerfile.verify` and `verify.sh` to standardize validation.
5. Run `./verify.sh` and record the command and output in the writeup.
