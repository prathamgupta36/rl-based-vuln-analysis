#!/usr/bin/env bash
set -euo pipefail

image="frozenbinary-verify"
expected="MINUTEMAN{s3t_f1re_2_fr0zen_byt3s}"

docker build -f Dockerfile.verify -t "$image" .

output="$(docker run --rm "$image" python generated_solve.py | tr -d '\r')"
if [[ "$output" != *"$expected"* ]]; then
  echo "ERROR: generated_solve.py output did not contain expected flag" >&2
  exit 1
fi

echo "OK: generated_solve.py"
echo "All verification checks passed."
