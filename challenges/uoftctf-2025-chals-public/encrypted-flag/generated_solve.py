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
