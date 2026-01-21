# powerpuff - Reversing Writeup (Codex)

## Goal
Recover the secret ingredient and the full flag from the `challenge` binary.

## High-level Observation
`main` reads user input and compares it against a hardcoded string using `strcmp`.
If it matches, it prints `MINUTEMAN{...}` and calls `print_flag()` which XOR-decodes
an embedded byte array.

## Core Insight
Two easy recovery paths:
1. `strings`/disassembly shows the secret input is `"salt"`.
2. `print_flag()` XORs each byte with `0x3e`, so you can decode the suffix offline.

## Manual Decode
From `src.c`:
```
encoded = [0x6c, 0x51, 0x49, 0x5a, 0x47, 0x4c, 0x4b, 0x58, 0x58]
```
XOR each byte with `0x3e` → `Rowdyruff`.

## Generated Solver (Full)
Saved as `generated_solve.py` in this folder.

```py
encoded = [0x6C, 0x51, 0x49, 0x5A, 0x47, 0x4C, 0x4B, 0x58, 0x58]
decoded = "".join(chr(b ^ 0x3E) for b in encoded)
print(f"MINUTEMAN{{{decoded}}}")
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
