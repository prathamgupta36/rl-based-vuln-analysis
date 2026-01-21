# Encrypted Flag - Reversing Writeup (Codex)

## Goal
Recover the flag from an encrypted file and a stripped encryption binary.

## File Layout
- `dist/enc_flag.zip` contains `chall` (the encryptor) and `flag.enc`.
- `flag.enc` format: first 256 bytes are a custom AES S-box, followed by ciphertext blocks.
- `solve/aes.py` is a mutable AES implementation that lets us swap the S-box.

## Key Insight
The binary generates a custom S-box by inserting values 0..255 into an array using linear probing:
- For each value `n`, it chooses a random starting index.
- If the slot is occupied, it moves forward until it finds an empty slot.

Because the final S-box is included in `flag.enc`, we can invert this process:
for each `n`, only some starting indices are possible given the final placement.

The RNG matches glibc `random()` with a 31-bit additive feedback:
```
state[i] = (state[i-31] + state[i-3]) mod 2^31
```
The binary consumes 64 of these 31-bit states, using their bytes to place
the 256 S-box values. The next two states form the AES-128 key (little-endian).

## Reconstruction Approach
1. Read the 256-byte S-box from `flag.enc`.
2. For each value `n`, compute all possible RNG bytes that could have led to its final slot.
3. Combine each 4 bytes into 31-bit RNG state candidates (31 states total).
4. Use the additive recurrence to roll forward to state 64 while filtering by S-box constraints.
5. Form key candidates from states 64 and 65, then decrypt and test for `uoftctf`.

## Generated Solver (Full)
Saved as `generated_solve.py` in this folder.

```py
import itertools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "solve"))

import aes  # noqa: E402


def divide_chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def check_possible(sbox, n, rand_idx):
    idx = sbox.index(n)
    while rand_idx != idx:
        if sbox[rand_idx] > n:
            return False
        rand_idx = (rand_idx + 1) % 256
    return True


def check_full(sbox, state_index, rand_state):
    if (rand_state >> 24) >= 128:
        return False
    for j in range(4):
        if not check_possible(sbox, state_index * 4 + j, (rand_state >> (8 * j)) & 0xFF):
            return False
    return True


def extract_flag(plaintext):
    start = plaintext.find(b"uoftctf{")
    if start == -1:
        return None
    end = plaintext.find(b"}", start)
    if end == -1:
        return None
    return plaintext[start:end + 1].decode()


def main():
    enc_path = ROOT / "solve" / "flag.enc"
    data = enc_path.read_bytes()
    sbox = list(data[:256])
    enc = data[256:]

    aes.s_box = sbox
    aes.inv_s_box = [0] * 256
    for i in range(256):
        aes.inv_s_box[i] = sbox.index(i)

    curr_sbox = [-1] * 256
    rand_states = []

    for i in range(31 * 4):
        pos = []
        idx = sbox.index(i)
        curr_sbox[idx] = i
        while curr_sbox[idx] != -1:
            pos.append(idx)
            idx = (idx - 1) % 256
        rand_states.append(pos)

    rand_states = [
        [int.from_bytes(bytes(x), "little") for x in itertools.product(*group)]
        for group in divide_chunks(rand_states, 4)
    ]

    for i in range(31, 64):
        new_state = set()
        for a, b in itertools.product(rand_states[-31], rand_states[-3]):
            new_state.add((a + b) % (1 << 31))
            new_state.add((a + b + 1) % (1 << 31))
        rand_states.append([x for x in new_state if check_full(sbox, i, x)])

    for _ in range(64, 66):
        new_state = set()
        for a, b in itertools.product(rand_states[-31], rand_states[-3]):
            new_state.add((a + b) % (1 << 31))
            new_state.add((a + b + 1) % (1 << 31))
        rand_states.append([x for x in new_state if (x >> 24) < 128])

    possible_keys = rand_states[-2:]
    blocks = [enc[i:i + 16] for i in range(0, len(enc), 16)]

    for a in possible_keys[0]:
        for b in possible_keys[1]:
            key = a.to_bytes(8, "little") + b.to_bytes(8, "little")
            ciph = aes.AES(key)
            first = ciph.decrypt_block(blocks[0])
            if not first.startswith(b"uoftctf"):
                continue
            plaintext = b"".join(ciph.decrypt_block(block) for block in blocks)
            flag = extract_flag(plaintext)
            if flag:
                print(flag)
                return

    raise SystemExit("flag not found")


if __name__ == "__main__":
    main()
```

## Docker Validation
Executed in a clean container to verify both the original and generated solvers:

```bash
./verify.sh
```

Output:

```
OK: solve.py
OK: generated_solve.py
All verification checks passed.
```

## Reproducible Verification
Included for collaborators:
- `Dockerfile.verify` installs `tqdm` and copies the challenge files.
- `verify.sh` auto-extracts `dist/enc_flag.zip` into `solve/` if needed, then checks both solvers.

## Writeup Process (Reusable)
Use this sequence for future challenges to keep writeups reproducible:

1. Collect the challenge files, official solve script, and any existing writeups.
2. Reverse the binary and summarize the core insight.
3. Create a standalone `generated_solve.py` that prints the flag deterministically.
4. Add `Dockerfile.verify` and `verify.sh` to standardize validation.
5. Run `./verify.sh` and record the command and output in the writeup.
