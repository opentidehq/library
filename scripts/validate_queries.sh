#!/usr/bin/env bash
# Check every rule query offline (opentide validate --check queries), except
# the files listed in scripts/query-false-positives.txt.
set -euo pipefail
cd "$(dirname "$0")/.."
args=()
while IFS= read -r file; do
  args+=(--file "$file")
done < <(git ls-files 'objects/*.yaml' | grep -vxF -f <(grep -v -e '^#' -e '^$' scripts/query-false-positives.txt))
opentide validate --strict --check queries "${args[@]}"
