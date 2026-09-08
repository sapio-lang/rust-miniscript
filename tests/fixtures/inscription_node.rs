//! Generate actual library-finalized reveals for the independent Core test.
extern crate bitcoin;
extern crate sapio_miniscript as miniscript;
extern crate serde_json;

use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::util::sighash::{Prevouts, SighashCache};
use bitcoin::util::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{Address, Network, OutPoint, SchnorrSig, SchnorrSighashType};
use bitcoin::{Script, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};
use miniscript::ord::Inscription;
use miniscript::psbt::PsbtExt;
use miniscript::{Miniscript, Tap, Terminal};
use serde_json::{json, Value};
use std::io::{self, Read};
use std::str::FromStr;
use std::sync::Arc;

type Ms = Miniscript<XOnlyPublicKey, Tap>;

fn keypair(byte: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    )
}

fn cases() -> Vec<(&'static str, Script, bool)> {
    let owner = keypair(1).x_only_public_key().0;
    let pk = Ms::from_str(&format!("pk({})", owner)).unwrap();
    let mut cases = Vec::new();
    for (name, size, count, postfix) in [
        ("prefix-empty", 0, 1, false),
        ("postfix-521", 521, 1, true),
        ("prefix-chunks", 1041, 1, false),
        ("postfix-multiple", 520, 3, true),
        ("prefix-threshold", 521, 1, false),
    ] {
        let mut inscription = Inscription::new(
            Some(b"application/octet-stream".to_vec()),
            Some(vec![0x5a; size]),
        );
        inscription.metadata = Some(vec![0x42; size]);
        let child = if name == "prefix-threshold" {
            Ms::from_str(&format!(
                "multi_a(2,{},{},{})",
                owner,
                keypair(2).x_only_public_key().0,
                keypair(3).x_only_public_key().0
            ))
            .unwrap()
        } else {
            pk.clone()
        };
        let items = Arc::new(vec![inscription; count]);
        let child = Arc::new(child);
        let ms = Ms::from_ast(if postfix {
            Terminal::InscribePost(items, child)
        } else {
            Terminal::InscribePre(items, child)
        })
        .unwrap();
        ms.sanity_check().unwrap();
        cases.push((name, ms.encode(), true));
    }
    // Sign a deliberately invalid script directly: the 520-byte limit also
    // applies to pushes in an unexecuted envelope. A valid control block and
    // signature ensure Core reaches the push-size check.
    let oversized = Builder::from(pk.encode().into_bytes())
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(b"ord")
        .push_slice(&[])
        .push_slice(&[0x5a; 521])
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();
    cases.push(("oversized-unexecuted-push", oversized, false));
    cases
}

fn vector(name: String, tx: &Transaction, allowed: bool, reason: &str) -> Value {
    json!({"name": name, "hex": serialize(tx).to_hex(), "allowed": allowed,
           "reject_contains": reason})
}

fn main() {
    let secp = Secp256k1::new();
    let internal = keypair(4).x_only_public_key().0;
    let cases = cases();
    let spend_info: Vec<_> = cases
        .iter()
        .map(|(_, script, _)| {
            TaprootBuilder::new()
                .add_leaf(0, script.clone())
                .unwrap()
                .finalize(&secp, internal)
                .unwrap()
        })
        .collect();
    if std::env::args().nth(1).as_deref() == Some("addresses") {
        let addresses: Vec<_> = spend_info
            .iter()
            .map(|info| Address::p2tr_tweaked(info.output_key(), Network::Regtest).to_string())
            .collect();
        println!("{}", json!(addresses));
        return;
    }
    assert_eq!(std::env::args().nth(1).as_deref(), Some("spends"));
    let mut funding_hex = String::new();
    io::stdin().read_to_string(&mut funding_hex).unwrap();
    let funding: Transaction = deserialize(&Vec::from_hex(funding_hex.trim()).unwrap()).unwrap();
    let mut vectors = Vec::new();
    for ((name, script, valid), info) in cases.into_iter().zip(spend_info) {
        let spk = Script::new_v1_p2tr_tweaked(info.output_key());
        let (vout, prevout) = funding
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| output.script_pubkey == spk)
            .unwrap();
        assert_eq!(prevout.value, 100_000);
        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(funding.txid(), vout as u32),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: 90_000,
                script_pubkey: spk,
            }],
        };
        let leaf = (script.clone(), LeafVersion::TapScript);
        let leaf_hash = TapLeafHash::from_script(&script, leaf.1);
        let control = info.control_block(&leaf).unwrap();
        let hash_ty = SchnorrSighashType::Default;
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(prevout)),
                leaf_hash,
                hash_ty,
            )
            .unwrap();
        let message = Message::from_digest_slice(&sighash[..]).unwrap();
        let sign = |byte| SchnorrSig {
            sig: secp.sign_schnorr_no_aux_rand(&message, &keypair(byte)),
            hash_ty,
        };
        if valid {
            let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
            psbt.inputs[0].witness_utxo = Some(prevout.clone());
            psbt.inputs[0].tap_scripts.insert(control, leaf);
            for byte in 1..=3 {
                psbt.inputs[0]
                    .tap_script_sigs
                    .insert((keypair(byte).x_only_public_key().0, leaf_hash), sign(byte));
            }
            psbt.finalize_mut(&secp).unwrap();
            tx = psbt.extract(&secp).unwrap();
        } else {
            tx.input[0].witness = Witness::from_vec(vec![
                sign(1).to_vec(),
                script.into_bytes(),
                control.serialize(),
            ]);
        }
        vectors.push(vector(
            name.into(),
            &tx,
            valid,
            if valid {
                ""
            } else {
                "Push value size limit exceeded"
            },
        ));
        if !valid {
            continue;
        }
        for mutation in ["signature", "inscription", "control", "output"] {
            let mut corrupted = tx.clone();
            let mut witness = corrupted.input[0].witness.to_vec();
            let len = witness.len();
            match mutation {
                "signature" => {
                    witness
                        .iter_mut()
                        .take(len - 2)
                        .find(|arg| !arg.is_empty())
                        .unwrap()[0] ^= 1
                }
                "inscription" => {
                    let content_type = b"application/octet-stream";
                    let offset = witness[len - 2]
                        .windows(content_type.len())
                        .position(|bytes| bytes == content_type)
                        .unwrap();
                    witness[len - 2][offset] ^= 1;
                }
                "control" => witness[len - 1][1] ^= 1,
                "output" => corrupted.output[0].value -= 1,
                _ => unreachable!(),
            }
            corrupted.input[0].witness = Witness::from_vec(witness);
            vectors.push(vector(
                format!("{}-changed-{}", name, mutation),
                &corrupted,
                false,
                "",
            ));
        }
    }
    println!("{}", json!(vectors));
}
