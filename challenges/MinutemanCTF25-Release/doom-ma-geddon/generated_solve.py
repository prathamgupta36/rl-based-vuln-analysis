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
