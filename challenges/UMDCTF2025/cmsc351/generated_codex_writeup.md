# cmsc351 - Reversing Writeup (Codex)

## Goal
Find the sequence of `t`/`s` choices that makes `f0(285, 199, buf)` return true,
then use it to print the flag.

## High-level Observation
`src.c` is an auto-generated call-graph maze:
- `main` reads up to 24 characters and calls `f0(285, 199, buf)`.
- Each `fX` switches on `*choices` and recurses to another `fY`, consuming one
  character and updating two integer “fuel” values.
- There is a single base case: `f882` returns `fuel1 + fuel2 <= 0`.

So the problem reduces to: find a `t`/`s` string that reaches `f882` with a
non-positive fuel sum.

## Core Insight
Every transition uses the current `fuel2` to compute the next pair:
```
return fY(fuel2 - A, fuel2 - B, choices + 1);
```
So the full state can be represented as:
```
state = (function_id, fuel2, index_in_choices)
```
with `fuel1` derived from the previous `fuel2`.

This is a classic graph search:
1. Parse the source to extract edges for each `fX`.
2. Run DFS/BFS with memoization on `(fX, fuel2, depth)` to avoid cycles.
3. Stop when you reach `f882` and `fuel1 + fuel2 <= 0`.

The provided solution path is:
```
ttstttsssssttsssttt
```

## Generated Solver (Full)
Saved as `generated_solve.py` in this folder. It uses the solve string to run
the binary and print the flag.

```py
import subprocess
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    choices = (root / "solve.txt").read_text().strip()
    binary = root / "cmsc351"

    result = subprocess.check_output([str(binary)], input=(choices + "\n").encode())
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
