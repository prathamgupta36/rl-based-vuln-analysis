# deobfuscation - Reversing Writeup (Codex)

## Goal
Recover the flag from an obfuscated assembly challenge.

## High-level Observation
The provided `flag` file is a small ELF that reads a password, then checks it
against a stored transformation. The `src/flag.asm` reveals two arrays:
`encrypted_flag` and `key_bytes`, which are XORed to produce the plaintext flag.

## Core Insight
The obfuscation is just a byte-wise XOR:
```
flag[i] = encrypted_flag[i] ^ key_bytes[i]
```
So recovering the flag is a direct XOR across the two arrays.

## Generated Solver (Full)
Saved as `generated_solve.py` in this folder.

```py
encrypted_flag = [
    0x20, 0x22, 0x20, 0x26, 0x35, 0x37, 0x14, 0x07, 0x46, 0x00, 0x5A, 0x17,
    0x44, 0x35, 0x52, 0x0C, 0x70, 0x28, 0x37, 0x1C, 0x5B, 0x1D, 0x70, 0x16,
    0x76, 0x50, 0x69, 0x5C, 0x6E, 0x6C, 0x1B, 0x12, 0x54, 0x69, 0x2D, 0x38,
    0x06, 0x23, 0x11, 0x3D, 0x2F, 0x00, 0x02, 0x4A, 0x68, 0x45, 0x3B, 0x64,
    0x1A, 0x20, 0x55, 0x05,
]
key_bytes = [
    0x75, 0x6F, 0x64, 0x65, 0x61, 0x71, 0x6F, 0x75, 0x75, 0x76, 0x69, 0x45,
    0x60, 0x70, 0x7F, 0x65, 0x54, 0x77, 0x63, 0x74, 0x68, 0x42, 0x53, 0x54,
    0x45, 0x03, 0x3D, 0x7F, 0x31, 0x58, 0x75, 0x46, 0x75, 0x44, 0x60, 0x78,
    0x6A, 0x74, 0x51, 0x4F, 0x1C, 0x5F, 0x76, 0x79, 0x0B, 0x2D, 0x75, 0x45,
    0x4B, 0x55, 0x66, 0x78,
]

flag = "".join(chr(e ^ k) for e, k in zip(encrypted_flag, key_bytes))
print(flag)
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
