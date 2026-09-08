extern crate bitcoin;
extern crate sapio_miniscript as miniscript;

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::util::schnorr::TapTweak;
use bitcoin::util::sighash::{Prevouts, SighashCache};
use bitcoin::util::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{EcdsaSig, EcdsaSighashType, OutPoint, PublicKey, SchnorrSig, SchnorrSighashType};
use bitcoin::{Script, Transaction, TxIn, TxOut, XOnlyPublicKey};
use miniscript::psbt::{interpreter_check, Error, InputError, PsbtExt};
use miniscript::{Miniscript, Tap};
use std::str::FromStr;

fn transaction(script_pubkey: Script) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: 10_000,
            script_pubkey,
        }],
    }
}

fn taproot_psbt(hash_ty: SchnorrSighashType, script_spend: bool) -> Psbt {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
    let public_key = keypair.x_only_public_key().0;
    let script = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!("pk({})", public_key))
        .unwrap()
        .encode();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, public_key)
        .unwrap();
    let funding = transaction(Script::new_v1_p2tr_tweaked(spend_info.output_key()));
    let mut tx = transaction(Script::new());
    tx.input[0].previous_output = OutPoint::new(funding.txid(), 0);
    let leaf = (script, LeafVersion::TapScript);
    let leaf_hash = TapLeafHash::from_script(&leaf.0, leaf.1);
    let prevouts = Prevouts::All(&funding.output);
    let mut cache = SighashCache::new(&tx);
    let hash = if script_spend {
        cache.taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, hash_ty)
    } else {
        cache.taproot_key_spend_signature_hash(0, &prevouts, hash_ty)
    }
    .unwrap();
    let signing_key = if script_spend {
        keypair
    } else {
        keypair
            .tap_tweak(&secp, spend_info.merkle_root())
            .into_inner()
    };
    let signature = SchnorrSig {
        sig: secp.sign_schnorr_no_aux_rand(
            &Message::from_digest_slice(&hash[..]).unwrap(),
            &signing_key,
        ),
        hash_ty,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
    if script_spend {
        psbt.inputs[0]
            .tap_script_sigs
            .insert((public_key, leaf_hash), signature);
        psbt.inputs[0]
            .tap_scripts
            .insert(spend_info.control_block(&leaf).unwrap(), leaf);
    } else {
        psbt.inputs[0].tap_key_sig = Some(signature);
    }
    psbt
}

fn ecdsa_psbt(hash_ty: EcdsaSighashType) -> Psbt {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let public_key = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp, &secret,
    ));
    let script = Script::new_p2pk(&public_key);
    let funding = transaction(script.clone());
    let mut tx = transaction(Script::new());
    tx.input[0].previous_output = OutPoint::new(funding.txid(), 0);
    let hash = SighashCache::new(&tx)
        .legacy_signature_hash(0, &script, hash_ty.to_u32())
        .unwrap();
    let signature = EcdsaSig {
        sig: secp.sign_ecdsa(&Message::from_digest_slice(&hash[..]).unwrap(), &secret),
        hash_ty,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].non_witness_utxo = Some(funding);
    psbt.inputs[0].partial_sigs.insert(public_key, signature);
    psbt
}

fn assert_mismatch(error: Error, required: u32, got: u32) {
    match error {
        Error::InputError(
            InputError::SighashMismatch {
                required: found,
                got: actual,
            },
            0,
        ) => {
            assert_eq!((found, actual), (required, got));
        }
        other => panic!("expected sighash mismatch, got {:?}", other),
    }
}

fn assert_rejected_without_mutation(mut psbt: Psbt, required: u32, got: u32) {
    let secp = Secp256k1::verification_only();
    let before = psbt.clone();
    assert_mismatch(psbt.finalize_inp_mut(&secp, 0).unwrap_err(), required, got);
    assert_eq!(psbt, before);
    let errors = psbt.finalize_mut(&secp).unwrap_err();
    assert_eq!(errors.len(), 1);
    assert_mismatch(errors.into_iter().next().unwrap(), required, got);
    assert_eq!(psbt, before);
    if psbt.inputs[0].final_script_sig.is_some() || psbt.inputs[0].final_script_witness.is_some() {
        assert_mismatch(interpreter_check(&psbt, &secp).unwrap_err(), required, got);
        assert_mismatch(psbt.extract(&secp).unwrap_err(), required, got);
    }
}

#[test]
fn matching_taproot_default_metadata_accepts_partial_and_final_signatures() {
    let secp = Secp256k1::verification_only();
    for &script_spend in &[false, true] {
        let mut psbt = taproot_psbt(SchnorrSighashType::Default, script_spend);
        psbt.inputs[0].sighash_type = Some(SchnorrSighashType::Default.into());
        psbt.finalize_mut(&secp).unwrap();
        psbt.extract(&secp).unwrap();
        psbt.inputs[0].sighash_type = Some(SchnorrSighashType::Default.into());
        psbt.finalize_mut(&secp).unwrap();
        psbt.extract(&secp).unwrap();
    }
}

#[test]
fn taproot_metadata_rejects_valid_none_signatures_before_mutation() {
    let secp = Secp256k1::verification_only();
    for &script_spend in &[false, true] {
        let partial = taproot_psbt(SchnorrSighashType::None, script_spend);
        // Independently verify that these are valid transaction signatures.
        let finalized = partial.clone().finalize(&secp).unwrap();
        finalized.extract(&secp).unwrap();
        for mut psbt in vec![partial, finalized] {
            psbt.inputs[0].sighash_type = Some(SchnorrSighashType::Default.into());
            assert_rejected_without_mutation(psbt, 0, SchnorrSighashType::None as u32);
        }
    }
}

#[test]
fn absent_metadata_allows_valid_non_all_signatures() {
    let secp = Secp256k1::verification_only();
    for psbt in vec![
        taproot_psbt(SchnorrSighashType::None, false),
        taproot_psbt(SchnorrSighashType::None, true),
        ecdsa_psbt(EcdsaSighashType::None),
    ] {
        assert!(psbt.inputs[0].sighash_type.is_none());
        psbt.finalize(&secp).unwrap().extract(&secp).unwrap();
    }
}

#[test]
fn ecdsa_metadata_rejects_valid_none_signatures_before_mutation() {
    let secp = Secp256k1::verification_only();
    let partial = ecdsa_psbt(EcdsaSighashType::None);
    let finalized = partial.clone().finalize(&secp).unwrap();
    finalized.extract(&secp).unwrap();
    for mut psbt in vec![partial, finalized] {
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::All.into());
        assert_rejected_without_mutation(psbt, 1, 2);
    }
}

#[test]
fn taproot_metadata_also_checks_unused_partial_signatures() {
    let mut psbt = taproot_psbt(SchnorrSighashType::Default, false);
    let script_psbt = taproot_psbt(SchnorrSighashType::None, true);
    assert_eq!(psbt.unsigned_tx, script_psbt.unsigned_tx);
    psbt.inputs[0].tap_script_sigs = script_psbt.inputs[0].tap_script_sigs.clone();
    psbt.inputs[0].sighash_type = Some(SchnorrSighashType::Default.into());
    assert_rejected_without_mutation(psbt, 0, 2);
}
