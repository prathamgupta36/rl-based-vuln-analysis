#!/usr/bin/env bash
set -euo pipefail

image="umdctf-deobfuscation-verify"
expected='UMDCTF{r3v3R$E-i$_Th3_#B3ST#_4nT!-M@lW@r3_t3chN!Qu3}'

docker build -f Dockerfile.verify -t "$image" .

output="$(docker run --rm "$image" python generated_solve.py | tr -d '\r')"
if [[ "$output" != *"$expected"* ]]; then
  echo "ERROR: generated_solve.py output did not contain expected flag" >&2
  exit 1
fi

echo "OK: generated_solve.py"
echo "All verification checks passed."
