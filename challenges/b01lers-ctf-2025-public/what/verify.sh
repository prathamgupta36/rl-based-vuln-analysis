#!/usr/bin/env bash
set -euo pipefail

image="b01lers-what-verify"
expected="bctf{1m_p3rplexed_to_s4y_th3_v3ry_l34st_rzr664k1p5v2qe4qdkym}"

docker build -f Dockerfile.verify -t "$image" .

run_and_check() {
  local script_path="$1"
  local output

  output="$(docker run --rm "$image" python "$script_path" | tr -d '\r')"
  if [[ "$output" != *"$expected"* ]]; then
    echo "ERROR: $script_path output did not contain expected flag" >&2
    exit 1
  fi
  echo "OK: $script_path"
}

run_and_check solve/what_solve.py
run_and_check generated_solve.py

echo "All verification checks passed."
