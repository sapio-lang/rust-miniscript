#!/usr/bin/env bash
#
# Do pinning as required for current MSRV.

set -euo pipefail

cargo update -p cc --precise 1.0.79

# Optional encoding releases otherwise force hex 1.1+, which needs 1.74.
# The encoding feature is not enabled by Miniscript.
cargo update -p bitcoin-consensus-encoding --precise 1.0.0
cargo update -p hex-conservative:1 --precise 1.0.0

# The inscription vector reader introduces these test-only dependencies.
cargo update -p itoa --precise 1.0.15
cargo update -p ryu --precise 1.0.20
