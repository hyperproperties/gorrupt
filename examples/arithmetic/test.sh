#!/bin/bash
set -e

go test -count=1 -timeout=0 -v -json  ./ > test-results
