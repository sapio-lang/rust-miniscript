#!/usr/bin/env bash
#
# Do pinning as required for current MSRV.

set -euo pipefail

cargo update -p cc --precise 1.0.79

# The inscription vector reader introduces these test-only dependencies.
cargo update -p itoa --precise 1.0.15
cargo update -p ryu --precise 1.0.20
