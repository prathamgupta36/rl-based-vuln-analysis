#!/usr/bin/env bash
set -euo pipefail

image="encrypted-flag-verify"
expected="uoftctf{175_ju57_435_bu7_w0r53}"

if [ ! -f solve/flag.enc ]; then
  unzip -o dist/enc_flag.zip -d solve
fi

docker build -f Dockerfile.verify -t "$image" .

run_and_check() {
  local workdir="$1"
  local script="$2"
  local output

  output="$(docker run --rm -w "$workdir" "$image" python "$script" | tr -d '\r')"
  if [[ "$output" != *"$expected"* ]]; then
    echo "ERROR: $script output did not contain expected flag" >&2
    exit 1
  fi
  echo "OK: $script"
}

run_and_check /work/solve solve.py
run_and_check /work generated_solve.py

echo "All verification checks passed."
