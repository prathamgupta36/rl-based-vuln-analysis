#!/usr/bin/env bash
set -euo pipefail

image="umdctf-cmsc351-verify"
expected="UMDCTF{C4ll_Gr4ph5_ar3_st1ll_gr4ph5}"

docker build -f Dockerfile.verify -t "$image" .

output="$(docker run --rm "$image" python generated_solve.py | tr -d '\r')"
if [[ "$output" != *"$expected"* ]]; then
  echo "ERROR: generated_solve.py output did not contain expected flag" >&2
  exit 1
fi

echo "OK: generated_solve.py"
echo "All verification checks passed."
