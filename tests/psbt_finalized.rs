// SPDX-License-Identifier: CC0-1.0

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    absolute, transaction, Amount, PublicKey, Sequence, Transaction, TxIn, TxOut, Witness,
};
use miniscript::psbt::{interpreter_check, PsbtExt};
use miniscript::{Miniscript, Segwitv0};

fn finalized_timelock(policy: &str) -> Psbt {
    let script = Miniscript::<PublicKey, Segwitv0>::from_str_insane(policy)
        .unwrap()
        .encode();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_consensus(100),
        input: vec![TxIn { sequence: Sequence(6), ..TxIn::default() }],
        output: vec![TxOut { value: Amount::from_sat(900), script_pubkey: script.to_p2wsh() }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo =
        Some(TxOut { value: Amount::from_sat(1000), script_pubkey: script.to_p2wsh() });
    psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[script.as_bytes()]));
    psbt
}

fn assert_rejected(mut psbt: Psbt) {
    let secp = Secp256k1::verification_only();
    let original = psbt.clone();
    assert!(psbt.finalize_inp_mut(&secp, 0).is_err());
    assert_eq!(psbt, original);
    assert!(psbt.finalize_mut(&secp).is_err());
    assert_eq!(psbt, original);
    assert!(interpreter_check(&psbt, &secp).is_err());
    assert!(psbt.extract(&secp).is_err());
}

#[test]
fn finalized_csv_requires_transaction_version_and_enabled_sequence() {
    let secp = Secp256k1::verification_only();
    let original = finalized_timelock("older(6)");
    original
        .clone()
        .finalize_mall(&secp)
        .unwrap()
        .extract(&secp)
        .unwrap();
    let mut version_one = original.clone();
    version_one.unsigned_tx.version = transaction::Version::ONE;
    assert_rejected(version_one);
    let mut disabled = original;
    disabled.unsigned_tx.input[0].sequence = Sequence(0x80000006);
    assert_rejected(disabled);
}

#[test]
fn finalized_cltv_requires_nonfinal_sequence() {
    let secp = Secp256k1::verification_only();
    let mut psbt = finalized_timelock("after(100)");
    psbt.clone()
        .finalize_mall(&secp)
        .unwrap()
        .extract(&secp)
        .unwrap();
    psbt.unsigned_tx.input[0].sequence = Sequence::MAX;
    assert_rejected(psbt);
}
