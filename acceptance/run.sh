#!/usr/bin/env bash
# Run the internal_ca unit tests and the 30-certificate acceptance harness.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> unit tests (v3/lints/community InternalCA)"
( cd ../v3 && go test ./lints/community/ -run InternalCA )

echo "==> 30-certificate acceptance + traceability report"
go run . "$@"

echo
echo "Report: $(pwd)/report.md"
