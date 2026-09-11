extern crate bitcoin;
extern crate miniscript;

use std::str::FromStr;

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    absolute, transaction, Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use miniscript::ord::Inscription;
use miniscript::psbt::{interpreter_check, PsbtExt};
use miniscript::{Miniscript, Segwitv0, Tap};

#[derive(Clone, Copy, Debug)]
enum SpendKind {
    Wsh,
    Taproot,
}

impl SpendKind {
    fn key(self, byte: u8) -> String {
        let public_key = public_key(byte);
        match self {
            SpendKind::Wsh => public_key.to_string(),
            SpendKind::Taproot => public_key.inner.x_only_public_key().0.to_string(),
        }
    }

    fn script(self, expression: &str) -> ScriptBuf {
        match self {
            SpendKind::Wsh => Miniscript::<PublicKey, Segwitv0>::from_str(expression)
                .unwrap()
                .encode(),
            SpendKind::Taproot => Miniscript::<XOnlyPublicKey, Tap>::from_str(expression)
                .unwrap()
                .encode(),
        }
    }

    fn witness_tail(self) -> usize {
        match self {
            SpendKind::Wsh => 1,
            SpendKind::Taproot => 2,
        }
    }
}

fn public_key(byte: u8) -> PublicKey {
    PublicKey::new(SecpPublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    ))
}

fn envelope(body: &[u8]) -> String {
    Inscription::new(Some(b"text/plain".to_vec()), Some(body.to_vec())).to_string()
}

struct Spend {
    kind: SpendKind,
    script: ScriptBuf,
    psbt: Psbt,
}

impl Spend {
    fn new(kind: SpendKind, expression: &str) -> Self {
        Self::from_script(kind, kind.script(expression))
    }

    fn from_script(kind: SpendKind, script: ScriptBuf) -> Self {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn { sequence: Sequence(16), ..TxIn::default() }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new_p2pk(&public_key(9)),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let spk = match kind {
            SpendKind::Wsh => {
                psbt.inputs[0].witness_script = Some(script.clone());
                script.to_p2wsh()
            }
            SpendKind::Taproot => {
                let spend_info = TaprootBuilder::new()
                    .add_leaf(0, script.clone())
                    .unwrap()
                    .finalize(&Secp256k1::new(), public_key(9).inner.x_only_public_key().0)
                    .unwrap();
                let leaf = (script.clone(), LeafVersion::TapScript);
                psbt.inputs[0]
                    .tap_scripts
                    .insert(spend_info.control_block(&leaf).unwrap(), leaf);
                ScriptBuf::new_p2tr_tweaked(spend_info.output_key())
            }
        };
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut { value: Amount::from_sat(100_000), script_pubkey: spk }],
        };
        psbt.unsigned_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
        Spend { kind, script, psbt }
    }

    // Sign after setting locktime/version/sequence so rejection of invalid
    // timelocks cannot be explained by a stale transaction signature.
    fn sign(&mut self, keys: &[u8]) {
        let secp = Secp256k1::new();
        for byte in keys {
            let secret = SecretKey::from_slice(&[*byte; 32]).unwrap();
            let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
            match self.kind {
                SpendKind::Wsh => {
                    let hash_ty = EcdsaSighashType::All;
                    let hash = cache
                        .p2wsh_signature_hash(
                            0,
                            &self.script,
                            self.psbt.inputs[0].witness_utxo.as_ref().unwrap().value,
                            hash_ty,
                        )
                        .unwrap();
                    self.psbt.inputs[0].partial_sigs.insert(
                        public_key(*byte),
                        bitcoin::ecdsa::Signature {
                            signature: secp.sign_ecdsa(
                                &Message::from_digest_slice(&hash[..]).unwrap(),
                                &secret,
                            ),
                            sighash_type: hash_ty,
                        },
                    );
                }
                SpendKind::Taproot => {
                    let leaf_hash = TapLeafHash::from_script(&self.script, LeafVersion::TapScript);
                    let prevouts = vec![self.psbt.inputs[0].witness_utxo.clone().unwrap()];
                    let hash_ty = TapSighashType::Default;
                    let hash = cache
                        .taproot_script_spend_signature_hash(
                            0,
                            &Prevouts::All(&prevouts),
                            leaf_hash,
                            hash_ty,
                        )
                        .unwrap();
                    let keypair = Keypair::from_secret_key(&secp, &secret);
                    self.psbt.inputs[0].tap_script_sigs.insert(
                        (keypair.x_only_public_key().0, leaf_hash),
                        bitcoin::taproot::Signature {
                            signature: secp.sign_schnorr_no_aux_rand(
                                &Message::from_digest_slice(&hash[..]).unwrap(),
                                &keypair,
                            ),
                            sighash_type: hash_ty,
                        },
                    );
                }
            }
        }
    }

    fn finalize(mut self) -> Psbt {
        let secp = Secp256k1::new();
        self.psbt
            .finalize_mut(&secp)
            .unwrap_or_else(|error| panic!("{:?} {}: {:?}", self.kind, self.script, error));
        interpreter_check(&self.psbt, &secp).unwrap();
        let tx = self.psbt.extract(&secp).unwrap();
        let witness = tx.input[0].witness.to_vec();
        assert_eq!(witness[witness.len() - self.kind.witness_tail()], self.script.as_bytes());
        self.psbt
    }
}

fn assert_finalized_rejected(psbt: &Psbt) {
    let secp = Secp256k1::new();
    assert!(interpreter_check(psbt, &secp).is_err());
    assert!(psbt.extract(&secp).is_err());
}

#[test]
fn multiple_and_nested_inscriptions_bind_signatures_to_the_transaction() {
    let a = envelope(b"first");
    let b = envelope(b"second");
    for &kind in &[SpendKind::Wsh, SpendKind::Taproot] {
        let key = kind.key(1);
        for expression in &[
            format!("inscribe_pre({}{},pk({}))", a, b, key),
            format!("inscribe_post({}{},pk({}))", a, b, key),
            format!("inscribe_pre({},inscribe_post({},pk({})))", a, b, key),
        ] {
            let mut spend = Spend::new(kind, expression);
            spend.sign(&[1]);
            let finalized = spend.finalize();
            for mutation in 0..6 {
                let mut changed = finalized.clone();
                match mutation {
                    0 => changed.unsigned_tx.output[0].value -= Amount::ONE_SAT,
                    1 => changed.unsigned_tx.input[0].previous_output.vout += 1,
                    2 => changed.unsigned_tx.input[0].sequence.0 += 1,
                    3 => changed.unsigned_tx.version.0 += 1,
                    4 => {
                        changed.unsigned_tx.lock_time = absolute::LockTime::from_consensus(
                            changed.unsigned_tx.lock_time.to_consensus_u32() + 1,
                        )
                    }
                    5 => changed.inputs[0].witness_utxo.as_mut().unwrap().value -= Amount::ONE_SAT,
                    _ => unreachable!(),
                }
                assert_finalized_rejected(&changed);
            }
        }
    }
}

#[test]
fn inscribed_branches_require_the_selected_key_and_minimal_selector() {
    for &kind in &[SpendKind::Wsh, SpendKind::Taproot] {
        let expression = format!(
            "or_i(inscribe_pre({},pk({})),inscribe_post({},pk({})))",
            envelope(b"left"),
            kind.key(1),
            envelope(b"right"),
            kind.key(2)
        );
        let mut absent = Spend::new(kind, &expression);
        assert!(absent.psbt.finalize_mut(&Secp256k1::new()).is_err());
        for key in &[1, 2] {
            let mut spend = Spend::new(kind, &expression);
            spend.sign(&[*key]);
            let finalized = spend.finalize();
            let witness = finalized.inputs[0]
                .final_script_witness
                .as_ref()
                .unwrap()
                .to_vec();
            let selector = witness.len() - kind.witness_tail() - 1;
            assert_eq!(witness[selector], if *key == 1 { vec![1] } else { vec![] });
            for replacement in &[vec![2], vec![0], if *key == 1 { vec![] } else { vec![1] }] {
                let mut changed = finalized.clone();
                let mut changed_witness = witness.clone();
                changed_witness[selector] = replacement.clone();
                changed.inputs[0].final_script_witness =
                    Some(Witness::from_slice(&changed_witness));
                assert_finalized_rejected(&changed);
            }
            let mut dirty = finalized.clone();
            let mut dirty_witness = witness.clone();
            dirty_witness.insert(0, vec![1]);
            dirty.inputs[0].final_script_witness = Some(Witness::from_slice(&dirty_witness));
            assert_finalized_rejected(&dirty);
        }
    }
}

#[test]
fn inscribed_threshold_requires_two_distinct_signatures() {
    for &kind in &[SpendKind::Wsh, SpendKind::Taproot] {
        let expression = format!(
            "thresh(2,inscribe_pre({},pk({})),s:inscribe_post({},pk({})),a:inscribe_pre({},pk({})))",
            envelope(b"one"), kind.key(1), envelope(b"two"), kind.key(2), envelope(b"three"), kind.key(3)
        );
        for keys in &[vec![1, 2], vec![1, 3], vec![2, 3]] {
            let mut spend = Spend::new(kind, &expression);
            spend.sign(keys);
            let finalized = spend.finalize();
            let witness = finalized.inputs[0]
                .final_script_witness
                .as_ref()
                .unwrap()
                .to_vec();
            let stack = &witness[..witness.len() - kind.witness_tail()];
            assert_eq!(stack.len(), 3);
            assert_eq!(stack.iter().filter(|item| !item.is_empty()).count(), 2);
            let mut missing = finalized.clone();
            let mut missing_witness = witness.clone();
            let index = stack.iter().position(|item| !item.is_empty()).unwrap();
            missing_witness[index].clear();
            missing.inputs[0].final_script_witness = Some(Witness::from_slice(&missing_witness));
            assert_finalized_rejected(&missing);
        }
        for keys in &[vec![], vec![1], vec![2], vec![3]] {
            let mut spend = Spend::new(kind, &expression);
            spend.sign(keys);
            assert!(spend.psbt.finalize_mut(&Secp256k1::new()).is_err());
        }
    }
}

#[test]
fn inscriptions_preserve_cltv_and_csv_spending_boundaries() {
    for &kind in &[SpendKind::Wsh, SpendKind::Taproot] {
        for &(lock, value) in &[
            ("after", 100),
            ("after", 500_000_100),
            ("older", 16),
            ("older", (1 << 22) | 16),
        ] {
            let expression = format!(
                "and_v(v:inscribe_post({},{}({})),inscribe_pre({},pk({})))",
                envelope(b"timelock"),
                lock,
                value,
                envelope(b"owner"),
                kind.key(1)
            );
            for delta in &[0, 1] {
                let mut spend = Spend::new(kind, &expression);
                if lock == "after" {
                    spend.psbt.unsigned_tx.lock_time =
                        absolute::LockTime::from_consensus(value + delta);
                } else {
                    spend.psbt.unsigned_tx.input[0].sequence = Sequence(value + delta);
                }
                spend.sign(&[1]);
                spend.finalize();
            }
            for invalid in 0..4 {
                let mut spend = Spend::new(kind, &expression);
                if lock == "after" {
                    spend.psbt.unsigned_tx.lock_time = absolute::LockTime::from_consensus(value);
                    match invalid {
                        0 => {
                            spend.psbt.unsigned_tx.lock_time =
                                absolute::LockTime::from_consensus(value - 1)
                        }
                        1 => {
                            spend.psbt.unsigned_tx.lock_time =
                                absolute::LockTime::from_consensus(if value < 500_000_000 {
                                    500_000_000
                                } else {
                                    100
                                })
                        }
                        2 => spend.psbt.unsigned_tx.input[0].sequence = Sequence::MAX,
                        3 => continue,
                        _ => unreachable!(),
                    }
                } else {
                    spend.psbt.unsigned_tx.input[0].sequence = Sequence(value);
                    match invalid {
                        0 => spend.psbt.unsigned_tx.input[0].sequence = Sequence(value - 1),
                        1 => spend.psbt.unsigned_tx.input[0].sequence = Sequence(value ^ (1 << 22)),
                        2 => spend.psbt.unsigned_tx.version = transaction::Version::ONE,
                        3 => spend.psbt.unsigned_tx.input[0].sequence.0 |= 1 << 31,
                        _ => unreachable!(),
                    }
                }
                spend.sign(&[1]);
                assert!(spend.psbt.finalize_mut(&Secp256k1::new()).is_err());
            }
        }
    }
}

#[test]
fn inscribed_hashlocks_require_correct_preimages_and_a_signature() {
    let preimage = [7; 32];
    for &kind in &[SpendKind::Wsh, SpendKind::Taproot] {
        for hash in 0..4 {
            let hash_expression = match hash {
                0 => format!("sha256({})", sha256::Hash::hash(&preimage)),
                // Miniscript hash256 text uses script byte order, while the
                // sha256d Hash Display implementation reverses its bytes.
                1 => format!("hash256({})", miniscript::hash256::Hash::hash(&preimage)),
                2 => format!("hash160({})", hash160::Hash::hash(&preimage)),
                3 => format!("ripemd160({})", ripemd160::Hash::hash(&preimage)),
                _ => unreachable!(),
            };
            let expression = format!(
                "and_v(v:inscribe_post({},{}),inscribe_pre({},pk({})))",
                envelope(b"preimage"),
                hash_expression,
                envelope(b"signature"),
                kind.key(1)
            );
            for candidate in &[
                None,
                Some(vec![8; 32]),
                Some(vec![7; 31]),
                Some(preimage.to_vec()),
            ] {
                let mut spend = Spend::new(kind, &expression);
                if let Some(ref candidate) = *candidate {
                    let input = &mut spend.psbt.inputs[0];
                    match hash {
                        0 => {
                            input
                                .sha256_preimages
                                .insert(sha256::Hash::hash(&preimage), candidate.clone());
                        }
                        1 => {
                            input
                                .hash256_preimages
                                .insert(sha256d::Hash::hash(&preimage), candidate.clone());
                        }
                        2 => {
                            input
                                .hash160_preimages
                                .insert(hash160::Hash::hash(&preimage), candidate.clone());
                        }
                        3 => {
                            input
                                .ripemd160_preimages
                                .insert(ripemd160::Hash::hash(&preimage), candidate.clone());
                        }
                        _ => unreachable!(),
                    }
                }
                assert!(spend.psbt.clone().finalize_mut(&Secp256k1::new()).is_err());
                spend.sign(&[1]);
                if *candidate == Some(preimage.to_vec()) {
                    let finalized = spend.finalize();
                    let mut witness = finalized.inputs[0]
                        .final_script_witness
                        .as_ref()
                        .unwrap()
                        .to_vec();
                    let index = witness.iter().position(|item| item == &preimage).unwrap();
                    witness[index][0] ^= 1;
                    let mut invalid = finalized;
                    invalid.inputs[0].final_script_witness = Some(Witness::from_slice(&witness));
                    assert_finalized_rejected(&invalid);
                } else {
                    assert!(spend.psbt.finalize_mut(&Secp256k1::new()).is_err());
                }
            }
        }
    }
}

#[test]
fn taproot_signatures_bind_the_selected_inscription_leaf_and_control_block() {
    let kind = SpendKind::Taproot;
    let expressions = [
        format!("inscribe_pre({},pk({}))", envelope(b"first leaf"), kind.key(1)),
        format!("inscribe_post({},pk({}))", envelope(b"second leaf"), kind.key(1)),
    ];
    let scripts = [kind.script(&expressions[0]), kind.script(&expressions[1])];
    let secp = Secp256k1::new();
    let spend_info = TaprootBuilder::new()
        .add_leaf(1, scripts[0].clone())
        .unwrap()
        .add_leaf(1, scripts[1].clone())
        .unwrap()
        .finalize(&secp, public_key(9).inner.x_only_public_key().0)
        .unwrap();
    let funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        }],
    };
    for chosen in 0..2 {
        let mut spend = Spend::new(kind, &expressions[chosen]);
        spend.psbt.unsigned_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        spend.psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
        spend.psbt.inputs[0].tap_scripts.clear();
        for script in &scripts {
            let leaf = (script.clone(), LeafVersion::TapScript);
            spend.psbt.inputs[0]
                .tap_scripts
                .insert(spend_info.control_block(&leaf).unwrap(), leaf);
        }
        spend.sign(&[1]);
        let mut wrong_leaf = spend.psbt.clone();
        let key = public_key(1).inner.x_only_public_key().0;
        let leaf_hash = TapLeafHash::from_script(&scripts[chosen], LeafVersion::TapScript);
        let signature = wrong_leaf.inputs[0]
            .tap_script_sigs
            .remove(&(key, leaf_hash))
            .unwrap();
        let other_hash = TapLeafHash::from_script(&scripts[1 - chosen], LeafVersion::TapScript);
        wrong_leaf.inputs[0]
            .tap_script_sigs
            .insert((key, other_hash), signature);
        assert!(wrong_leaf.finalize_mut(&secp).is_err());

        let finalized = spend.finalize();
        let witness = finalized.inputs[0]
            .final_script_witness
            .as_ref()
            .unwrap()
            .to_vec();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[1], scripts[chosen].as_bytes());
        assert_eq!(witness[2].len(), 65);
        for mutation in 0..2 {
            let mut invalid = finalized.clone();
            let mut changed = witness.clone();
            if mutation == 0 {
                changed[1] = scripts[1 - chosen].as_bytes().to_vec();
            } else {
                changed[2][64] ^= 1;
            }
            invalid.inputs[0].final_script_witness = Some(Witness::from_slice(&changed));
            assert_finalized_rejected(&invalid);
        }
    }
}

#[test]
fn malleable_inscription_satisfaction_keeps_signature_and_preimage_checks() {
    let first = [3; 32];
    let second = [4; 32];
    let first_hash = sha256::Hash::hash(&first);
    let second_hash = sha256::Hash::hash(&second);
    let secp = Secp256k1::new();
    for &kind in &[SpendKind::Wsh, SpendKind::Taproot] {
        let expression = format!(
            "and_v(v:pk({}),or_i(inscribe_pre({},sha256({})),inscribe_post({},sha256({}))))",
            kind.key(1),
            envelope(b"first preimage"),
            first_hash,
            envelope(b"second preimage"),
            second_hash
        );
        // Both known hash preimages permit a third party to switch branches.
        // This intentionally requires the API for malleable satisfactions.
        let script = match kind {
            SpendKind::Wsh => Miniscript::<PublicKey, Segwitv0>::from_str_insane(&expression)
                .unwrap()
                .encode(),
            SpendKind::Taproot => Miniscript::<XOnlyPublicKey, Tap>::from_str_insane(&expression)
                .unwrap()
                .encode(),
        };
        let mut spend = Spend::from_script(kind, script);
        spend.psbt.inputs[0]
            .sha256_preimages
            .insert(first_hash, first.to_vec());
        spend.psbt.inputs[0]
            .sha256_preimages
            .insert(second_hash, second.to_vec());
        assert!(spend.psbt.clone().finalize_mall_mut(&secp).is_err());
        spend.sign(&[1]);
        assert!(spend.psbt.clone().finalize_mut(&secp).is_err());
        for single_input in &[false, true] {
            let mut finalized = spend.psbt.clone();
            if *single_input {
                finalized.finalize_inp_mall_mut(&secp, 0).unwrap();
            } else {
                finalized.finalize_mall_mut(&secp).unwrap();
            }
            interpreter_check(&finalized, &secp).unwrap();
            finalized.extract(&secp).unwrap();
            let mut witness = finalized.inputs[0]
                .final_script_witness
                .as_ref()
                .unwrap()
                .to_vec();
            let index = witness
                .iter()
                .position(|item| item == &first || item == &second)
                .unwrap();
            witness[index][0] ^= 1;
            finalized.inputs[0].final_script_witness = Some(Witness::from_slice(&witness));
            assert_finalized_rejected(&finalized);
        }
    }
}
