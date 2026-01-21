#!/usr/bin/env bash
set -euo pipefail

image="doom-ma-geddon-verify"
expected="MINUTEMAN{y0ur3_4n_h0n0r4ry_t3chn0m4nc3r_0f65b177}"

docker build -f Dockerfile.verify -t "$image" .

run_and_check() {
  local workdir="$1"
  local script_path="$2"
  local output

  output="$(docker run --rm -w "$workdir" "$image" python "$script_path" | tr -d '\r')"
  if [[ "$output" != *"$expected"* ]]; then
    echo "ERROR: $script_path output did not contain expected flag" >&2
    exit 1
  fi
  echo "OK: $script_path"
}

run_and_check /work/static /work/src/solve.py
run_and_check /work /work/generated_solve.py

echo "All verification checks passed."
