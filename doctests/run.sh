#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DOCTEST <<< "${DOCTEST:-nix run github:logos-co/logos-doctest --}"
if [ -e outputs ]; then chmod -R u+w outputs 2>/dev/null || true; fi
rm -rf outputs && mkdir -p outputs
for spec in *.test.yaml; do
  echo "==> Running ${spec}"
  "${DOCTEST[@]}" run "$spec" --output-dir outputs "$@"
done
