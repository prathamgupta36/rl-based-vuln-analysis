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
