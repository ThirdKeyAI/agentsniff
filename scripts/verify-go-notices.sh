#!/bin/sh
# Usage: verify-notices.sh <binary> <go-licenses report csv>
# Fails if a module embedded in the binary has no entry in the report.
set -eu
go version -m "$1" | awk -v report="$2" -v bin="$1" '
  BEGIN { while ((getline line < report) > 0) { split(line, f, ","); paths[f[1]] = 1 } }
  function covered(m,   p) { for (p in paths) if (p == m || index(p, m "/") == 1) return 1; return 0 }
  $1 == "dep" { if (prev != "" && !ok) missing = missing "\n  " prev; prev = $2; ok = covered($2); next }
  $1 == "=>"  { if (covered($2)) ok = 1; next }
  END {
    if (prev != "" && !ok) missing = missing "\n  " prev
    if (missing != "") { print "modules without a license notice in " bin ":" missing > "/dev/stderr"; exit 1 }
  }'
