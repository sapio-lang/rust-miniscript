![Build](https://github.com/sapio-lang/rust-miniscript/actions/workflows/rust.yml/badge.svg)

**Development and CI toolchain:** Rust 1.98.1, pinned in
[`rust-toolchain.toml`](rust-toolchain.toml) to match Sapio.

# Miniscript

Library for handling [Miniscript](http://bitcoin.sipa.be/miniscript/),
which is a subset of Bitcoin Script designed to support simple and general
tooling. Miniscripts represent threshold circuits of spending conditions,
and can therefore be easily visualized or serialized as human-readable
strings.

## High-Level Features

This library supports

* [Output descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
including embedded Miniscripts
* Parsing and serializing descriptors to a human-readable string format
* Compilation of abstract spending policies to Miniscript (enabled by the
`compiler` flag)
* Semantic analysis of Miniscripts and spending policies, with user-defined
public key types
* Encoding and decoding Miniscript as Bitcoin Script, given key types that
are convertible to `bitcoin::PublicKey`
* Determining satisfiability, and optimal witnesses, for a given descriptor;
completing an unsigned `bitcoin::TxIn` with appropriate data
* Determining the specific keys, hash preimages and timelocks used to spend
coins in a given Bitcoin transaction

More information can be found in [the documentation](https://docs.rs/miniscript)
or in [the `examples/` directory](https://github.com/apoelstra/rust-miniscript/tree/master/examples)


## Building and continuous integration

Use the pinned toolchain and committed lockfile:

```sh
rustup show
cargo test --locked --features compiler,use-serde,use-schemars,rand,trace
cargo check --locked --lib --target wasm32-unknown-unknown \
  --no-default-features --features compiler,use-serde,use-schemars
```

CI runs native tests and examples on Linux and macOS, tests the default build
and each of `compiler`, `use-serde`, `use-schemars`, and `rand` separately on
Linux, and checks Clippy, documentation, and the WASM library. The WASM check
uses Sapio's guest features; `rand` requires a host randomness source and is
covered by the native tests. WASM compilation requires a C compiler with a
WASM backend, selected with `CC_wasm32_unknown_unknown=clang` in CI.

The `unstable` feature enables nightly-only benchmarks, so it is excluded
from stable test commands. Older Rust versions are no longer tested; the
historical Rust 1.29 MSRV claim is not maintained by this fork.

The historical fuzz and live-node suites remain in `fuzz/` and
`integration_test/`, but are not part of this CI baseline. Their manifests
still refer to the upstream `miniscript` package name, and the integration
runner targets Bitcoin Core 22 with a missing checksum file. Restoring those
suites requires a separate update; passing native tests does not establish
fuzzing or live-node coverage. Formatting normalization is also a separate
task before a repository-wide formatting gate can be restored.


## CTV hashing and finalization

The CTV hash implementation is tested against all 400 expected hashes in the
official BIP-119 corpus. When any input has a scriptSig, the commitment includes
every input's serialized scriptSig, including empty ones.

Whole-transaction PSBT finalization establishes scriptSigs before satisfying
native witness inputs, then verifies the complete result. Regression tests cover
native WSH and Taproot CTV alongside a legacy input in either position, with both
fixed final scriptSigs and supplied signatures. Candidate satisfactions include
their own scriptSig in interpreter checks. The finalizer also validates PSBT
structure and enforces explicitly requested sighash types.

Single-input finalization checks the currently known scriptSigs. A later input
can change that commitment; use `PsbtExt::extract` or `interpreter_check` to
verify the complete transaction. Automatic ordering does not solve circular
P2SH CTV commitments or extend the set of accepted bare descriptors. Script
verification uses supplied prevouts; callers must authenticate funding data.

## Contributing
Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[##miniscript](https://web.libera.chat/?channels=##miniscript) on Libera.

# Release Notes

See [CHANGELOG.md](CHANGELOG.md).
