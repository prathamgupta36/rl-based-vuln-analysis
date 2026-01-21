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
