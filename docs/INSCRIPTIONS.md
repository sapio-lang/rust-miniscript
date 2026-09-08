# Inscription correctness and supported scope

This review covers the inscription extension introduced on `inscribor` and
published as `sapio-miniscript 7.0.2-alpha.0`. It checks script commitments,
Miniscript analysis and library finalization; it is not an Ord indexer audit.

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
| Spending | The interpreter could not evaluate inscription nodes. It now evaluates their wrapped condition. Real Schnorr tests finalize Taproot reveals and reject invalid signatures before and after finalization. |

The regressions are in `tests/inscription_envelopes.rs`,
`tests/inscription_parsing.rs`, and `tests/inscription_analysis.rs`. Defect tests
were run against the pre-repair source to establish that they fail. Signed
reveal tests also verify extracted witness script bytes and signature rejection.

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

These tests exercise the library interpreter and PSBT finalizer. They do not run
a Bitcoin node or Ord indexer, establish sat assignment/reinscription behavior,
or authenticate an inscription's funding history. Node execution and Ord index
comparison remain separate integration work.

[handbook]: https://docs.ordinals.com/inscriptions.html
[ord-parser]: https://github.com/ordinals/ord/blob/899e309424dd60e1c8065a7727a76d9b675a6ac4/src/inscriptions/envelope.rs
[bitcoin-interpreter]: https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp
