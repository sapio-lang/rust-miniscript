# Sapio extensions to Miniscript 13.1.0

This fork retains upstream package and feature names. Sapio adds transaction
commitments and inscription envelopes to the upstream AST, policy compiler,
satisfier, interpreter, and PSBT finalizer. Bitcoin types come from the compatible
0.32 release family; Sapio pins its Bitcoin dependency separately.

## Transaction commitments

`txtmpl(hash)` encodes `<hash32> OP_NOP4 OP_DROP` as a V fragment. Its meaning
assumes BIP119 CHECKTEMPLATEVERIFY enforcement; the opcode alone does not enforce
this condition on networks where it remains a NOP.

`Satisfier::check_tx_template` and the corresponding `AssetProvider` method
return false unless the caller supplies the transaction commitment. Interpreter
callers must supply that commitment with `with_tx_template`. The interpreter
checks it only when execution reaches the CTV fragment. PSBT finalization computes
the commitment from the candidate transaction, including finalized scriptSigs,
and rechecks finalized inputs against the completed transaction.

`tests/ctv_hash.rs` retains all 400 hashes in the official BIP119 vector file.
CTV finalization tests cover transaction mutation, finalized input ordering, and
unexecuted alternatives.

## Inscription envelopes

`inscribe_pre(hex,child)` and `inscribe_post(hex,child)` preserve exact script
bytes. The hex argument contains one or more canonical authored envelopes. The
concrete policy `inscribe(hex,child)` carries one inscription and an `Arc` child,
matching upstream policy traversal. Compilation retains all child conditions.

Discovery is deliberately more permissive than Miniscript decoding. A discovered
envelope may contain unknown fields or alternate encodings. Miniscript accepts
it only when reconstructing its fields produces the identical script. Push
minimality outside an envelope, field size bounds, execution stack and opcode
bounds, witness construction, and signature checks remain enforced.

Inscription effects survive policy translation, lifting, sorting, and
normalization. Semantic entailment returns `None` when either policy contains an
inscription because the entailment model does not describe inscription effects.

The 51 inscription regression tests exercise encoding boundaries, nested
combinators, compilation and resource bounds, discovery, and real signatures.
The `inscription_node_fixture` example and `contrib/check_inscriptions.py` retain
26 Bitcoin Core acceptance vectors, including 21 rejected mutations.

## Validation

Run the upstream and extension tests together:

```sh
cargo test --locked --features compiler,serde --lib --tests
cargo check --locked --no-default-features --features compiler,serde --lib
cargo build --locked --example inscription_node_fixture
python3 contrib/check_inscriptions.py --bitcoind /path/to/bitcoind \
  --fixture target/debug/examples/inscription_node_fixture
```

Sapio also carries a Bitcoin parser correction rejecting a 65-byte Taproot
signature with an explicit DEFAULT suffix. Its PSBT tests cover this boundary;
this fork uses Bitcoin's signature parser instead of maintaining a second one.
