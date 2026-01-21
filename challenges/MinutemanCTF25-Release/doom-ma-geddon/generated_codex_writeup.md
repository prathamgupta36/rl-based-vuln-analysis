# Doom-Ma-Geddon - Reversing Writeup (Codex)

## Goal
Recover the 50-byte flag accepted by the `doomageddon` binary.

## High-level Observation
The provided source (`src/doomageddon.c`) shows a large set of arithmetic and bitwise constraints over a 50-byte input. Manually solving 200+ constraints is tedious, so the intended approach is symbolic execution.

## Core Insight
`check()` applies deterministic constraints and returns `1` only for the correct flag. This is ideal for concolic execution:
- Treat stdin as symbolic bytes.
- Constrain bytes to printable ASCII.
- Ask the solver to find a path that reaches the "Correct!" branch.

## Solver Strategy (angr)
1. Load the binary with `auto_load_libs=False`.
2. Create a 50-byte symbolic stdin.
3. Constrain each byte to 0x20..0x7e.
4. Explore execution to the success address (`0x4031b8`) while avoiding failure (`0x4031c9`).
5. Extract the resulting model.

## Generated Solver (Full)
Saved as `generated_solve.py` in this folder.

```py
import angr
import claripy
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    binary = root / "static" / "doomageddon"

    project = angr.Project(str(binary), auto_load_libs=False)

    flag_len = 50
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(flag_len)]
    flag = claripy.Concat(*flag_chars)

    state = project.factory.full_init_state(args=[str(binary)], stdin=flag)
    for ch in flag_chars:
        state.solver.add(ch >= 0x20)
        state.solver.add(ch <= 0x7E)

    simgr = project.factory.simulation_manager(state)
    simgr.one_active.options.add(angr.options.LAZY_SOLVES)

    win_addr = 0x4031B8
    lose_addr = 0x4031C9
    simgr.explore(find=win_addr, avoid=lose_addr)

    if not simgr.found:
        raise SystemExit("flag not found")

    found = simgr.found[0]
    solution = found.solver.eval(flag, cast_to=bytes)
    print(solution.decode(errors="ignore"))


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
OK: /work/src/solve.py
OK: /work/generated_solve.py
All verification checks passed.
```

## Reproducible Verification
Included for collaborators:
- `Dockerfile.verify` installs `angr`.
- `verify.sh` runs both solvers and checks for the expected flag.

## Writeup Process (Reusable)
Use this sequence for future challenges to keep writeups reproducible:

1. Collect the challenge files, official solve script, and any existing writeups.
2. Reverse the binary and summarize the core insight.
3. Create a standalone `generated_solve.py` that prints the flag deterministically.
4. Add `Dockerfile.verify` and `verify.sh` to standardize validation.
5. Run `./verify.sh` and record the command and output in the writeup.
