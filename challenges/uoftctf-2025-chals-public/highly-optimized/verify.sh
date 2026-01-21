#!/usr/bin/env bash
set -euo pipefail

image="highly-optimized-verify"
expected="uoftctf{vmr00m_vmr00m}"

docker build -f Dockerfile.verify -t "$image" .

run_and_check() {
  local script_path="$1"
  local output

  output="$(docker run --rm "$image" python "$script_path")"
  if [ "$output" != "$expected" ]; then
    echo "ERROR: $script_path output '$output' (expected '$expected')" >&2
    exit 1
  fi
  echo "OK: $script_path"
}

run_and_check solve/solve.py
run_and_check generated_solve.py

echo "All verification checks passed."
