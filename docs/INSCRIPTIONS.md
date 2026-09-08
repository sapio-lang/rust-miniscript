# Inscription correctness and supported scope

This review covers the inscription extension introduced on `inscribor` and
published as `sapio-miniscript 7.0.2-alpha.0`. It checks script commitments,
Miniscript analysis, library finalization and reveal execution against Bitcoin
Core. It is not an Ord indexer audit.

## Reference behavior

The [Ordinal Theory Handbook][handbook] describes inscriptions as data pushes
inside an unexecuted `OP_FALSE OP_IF ... OP_ENDIF` envelope in a Taproot reveal.
The [Ord envelope parser][ord-parser] identifies envelopes and interprets their
fields. The [Bitcoin interpreter][bitcoin-interpreter] enforces the 520-byte
push limit even in an unexecuted branch, applies minimal-push checks to executed
pushes, and counts `IF`/`ENDIF` toward legacy opcode limits.

The Ord source reviewed here is revision
`899e309424dd60e1c8065a7727a76d9b675a6ac4`. Discovery and script reconstruction have
different requirements: a discovery parser can ignore unrecognized fields;
a Miniscript parser must preserve every committed script byte.

## Repairs and regression evidence

| Boundary | Defect and repaired behavior |
| --- | --- |
| Witness extraction | Empty/key-path witnesses underflowed; script-path witnesses selected the wrong item. Length checks select the script before its control block and optional annex. Tests cover zero/multiple arguments and input/envelope ordering. |
| Binary parsing | Ordinary field tags failed minimal-push parsing and inscription tokens had no decoder. Pre/post wrappers now round-trip inside B/K/V/W fragments; executable pushes retain minimality checks. |
| Text and artifacts | Post-wrapper argument order disagreed with Display, Debug could panic, and policy parsers omitted `inscribe`. Text and policy parsing now preserve the supported representation. |
| Script commitments | Permissive field discovery discarded unsupported fields or surrounding opcodes. Miniscript construction from script bytes rejects incomplete, empty or non-reconstructable representations. |
| Field encoding | Empty metadata disappeared, and unchunked fields could exceed 520 bytes. Empty metadata is retained; AST/policy validation rejects oversized fields. Body and metadata remain chunked. |
| Resource analysis | Multiple envelopes undercounted legacy opcodes; postfix VERIFY and stack use were underestimated; impossible paths became possible in metadata. Bounds now include each envelope and preserve impossible paths. |
| Keys and policies | Wrappers hid repeated keys and malformed children. Traversal and validation recurse; semantic filtering/sorting preserve reachable inscription metadata. Entailment explicitly rejects unsupported inscription effects. |
| Policy compilation | Wrapping compiled children recomputed their costs without branch probabilities and panicked, including for a single owner key. Wrappers now retain the child's compiled witness costs while accounting for their script bytes. |
| Spending | The interpreter could not evaluate inscription nodes. It now evaluates their wrapped condition. Real Schnorr tests finalize Taproot reveals and reject invalid signatures before and after finalization. |

The regressions are in `tests/inscription_envelopes.rs`,
`tests/inscription_parsing.rs`, `tests/inscription_analysis.rs`, and
`tests/inscription_compiler.rs`. Defect tests
were run against the pre-repair source to establish that they fail. Signed
reveal tests also verify extracted witness script bytes and signature rejection.

## Coverage of PR #3

The expanded suite adds 26 tests to the original 25 inscription regressions.
With all supported stable features, the complete crate suite passes 157 tests.
The tests use literal wire fixtures, separately built scripts and direct Bitcoin
Taproot commitments in addition to parser/encoder round trips.

| Boundary | Additional evidence |
| --- | --- |
| Authoring | All eight fields; absent/empty values; lengths 1/2, 75/76, 255/256, 519/520 and body/metadata chunk boundaries 521/1040/1041; numeric-opcode and non-UTF8 content bytes |
| Commitments | Binary/text/Serde and descriptor round trips, 64 generated field combinations, nested pre/post wrappers, combinators and a three-leaf Taproot tree |
| Rejection | All 5,040 header-field orders, all 249 unsupported one-byte tags, 1,686 truncation positions, 256 single-bit mutation parses, nonminimal pushes, noncanonical chunks and oversized fields |
| Discovery | Literal payloads and diagnostic flags for duplicate/dangling fields, empty values/body, unknown even/odd tags, pushnum values, stutter and incomplete or wrong protocol prefixes |
| Policies | Nested key/hash translation and callback errors, distinct inscription effects sharing a key, actual 3,600/3,601-byte witness-script bounds and compiler limits |
| Spending | Real ECDSA/WSH and Schnorr/Taproot finalization for nested/multiple envelopes, both branch choices, every 2-of-3 signer subset, height/time CLTV and CSV boundaries, all four hashlock families and malleable satisfaction APIs |
| Tampering | Missing/wrong signatures and preimages, nonminimal selectors, dirty stacks, changed outputs/outpoints/lock fields/funding amounts, switched Taproot leaves and altered Merkle proofs |

The mutation property requires every accepted script to re-encode exactly; it
does not assert that all valid mutations must be accepted. These are bounded,
deterministic cases, not an exhaustive search of arbitrary scripts. The compiler
can return `LimitsExceeded` after pruning a viable alternative representation;
the tests retain that documented search limitation while checking resource bounds.

A mutation check in an isolated copy confirmed that the new tests detect three
deliberately introduced faults: a wrong delegate field tag, discarded stutter
diagnostics and disabled exact-byte reconstruction checks. Each mutant compiled
and then failed assertions at runtime; the clean controls passed before and
after the experiment. This checks those oracles, not an overall mutation score.

## Independent Bitcoin Core check

CI also runs `contrib/check_inscriptions.py` against Bitcoin Core 31.1, with the
release archive pinned by its [official SHA256 checksum][core-checksums]. The
test creates a temporary regtest chain with networking disabled, funds the
fixture outputs and checks each candidate through [testmempoolaccept][core-rpc].
Candidates are checked separately and never submitted, so negative tests cannot
pass merely because an earlier candidate already spent the output.

Core accepts five library-finalized reveals covering prefix/postfix envelopes,
empty/chunked body and metadata, multiple envelopes, and a 2-of-3 condition.
It rejects 20 variants with changed signatures, inscription content, control
blocks or outputs. A separately signed invalid script also confirms that a
521-byte push is rejected inside an unexecuted envelope, with the expected
push-size error. These vectors use ordinary Taproot conditions, not native CTV.

Run the same check with a local Bitcoin Core installation:

```sh
cargo build --locked --example inscription_node_fixture
python3 contrib/check_inscriptions.py --bitcoind /path/to/bitcoind \
  --fixture target/debug/examples/inscription_node_fixture
```

The regular tests run in the existing Linux/macOS and optional-feature CI jobs;
the independent node check has a dedicated workflow job that fails on any
acceptance or rejection mismatch.

## Supported domain

The authoring model includes content type, content encoding, metaprotocol,
parent, delegate, pointer, metadata and body. It retains the existing single
parent representation. This is not complete support for every field or encoding
accepted by current Ord.

The discovery scanner remains permissive. Miniscript and policy parsers accept
only complete envelopes that the authoring model reconstructs byte for byte.
Unknown fields, alternative field ordering, noncanonical chunking, pushnum tags,
and other non-reconstructable encodings return errors rather than changing the
committed script. Empty content/body/metadata values remain representable.
Diagnostic flags on decoded inscriptions describe the parsed envelope; they do
not add fields to the authoring encoding. For example, chunked metadata can set
`duplicate_field` when parsed. Authored and parsed structs need not compare equal;
the payload and exact encoded script remain the round-trip guarantees.

`Inscription::validate` checks unchunked push sizes. Direct users of the raw
builder should call it before constructing scripts; Miniscript AST and concrete
policy validation call it automatically. The caller still authenticates funding
data, supplies the intended signing keys, and chooses an appropriate chain.

The tests do not run an Ord indexer, establish sat assignment/reinscription
behavior, or authenticate an inscription's funding history. Ord index comparison
and long-running coverage-guided fuzzing remain separate validation work.

[handbook]: https://docs.ordinals.com/inscriptions.html
[ord-parser]: https://github.com/ordinals/ord/blob/899e309424dd60e1c8065a7727a76d9b675a6ac4/src/inscriptions/envelope.rs
[bitcoin-interpreter]: https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp
[core-checksums]: https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS
[core-rpc]: https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/testmempoolaccept/
