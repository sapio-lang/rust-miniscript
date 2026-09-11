use std::str::FromStr;

use bitcoin::hex::FromHex;
extern crate serde_json;

use miniscript::bitcoin::consensus::deserialize;
use miniscript::bitcoin::hashes::sha256;
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::{PublicKey, ScriptBuf as Script, Transaction, Witness};
use miniscript::psbt::PsbtInputSatisfier;
use miniscript::Satisfier;

#[test]
fn matches_complete_bip119_hash_vectors() {
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("data/ctvhash.json")).unwrap();
    let mut transactions = 0;
    let mut hashes = 0;
    for entry in entries {
        // The official file includes a format header and a trailing comment.
        if entry.is_string() {
            continue;
        }
        let hex_tx = entry["hex_tx"].as_str().unwrap();
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(hex_tx).unwrap()).unwrap();
        let mut unsigned_tx = tx.clone();
        for input in &mut unsigned_tx.input {
            input.script_sig = Script::new();
            input.witness = Witness::default();
        }
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        for (input, tx_input) in psbt.inputs.iter_mut().zip(tx.input) {
            input.final_script_sig = Some(tx_input.script_sig);
            input.final_script_witness = Some(tx_input.witness);
        }
        let indices = entry["spend_index"].as_array().unwrap();
        let results = entry["result"].as_array().unwrap();
        assert_eq!(indices.len(), results.len());
        for (index, expected) in indices.iter().zip(results) {
            let index = index.as_u64().unwrap() as usize;
            let expected = sha256::Hash::from_str(expected.as_str().unwrap()).unwrap();
            // BIP-119 also supplies indices outside the transaction's inputs:
            // the hash commits to the supplied u32 without indexing the inputs.
            let satisfier = PsbtInputSatisfier::new(&psbt, index);
            assert!(
                <PsbtInputSatisfier as Satisfier<PublicKey>>::check_tx_template(
                    &satisfier, expected,
                ),
                "BIP-119 vector {} at input {}",
                transactions,
                index,
            );
            hashes += 1;
        }
        transactions += 1;
    }
    assert_eq!(transactions, 100);
    assert_eq!(hashes, 400);
}
