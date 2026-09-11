extern crate bitcoin;
extern crate miniscript;

use std::str::FromStr;

use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut,
    XOnlyPublicKey,
};
use miniscript::psbt::{interpreter_check, Error, InputError, PsbtExt};
use miniscript::{Miniscript, Tap};

fn transaction(script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut { value: bitcoin::Amount::from_sat(10_000), script_pubkey }],
    }
}

fn taproot_psbt(hash_ty: TapSighashType, script_spend: bool) -> Psbt {
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
    let funding = transaction(ScriptBuf::new_p2tr_tweaked(spend_info.output_key()));
    let mut tx = transaction(ScriptBuf::new());
    tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
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
            .to_keypair()
    };
    let signature = bitcoin::taproot::Signature {
        signature: secp.sign_schnorr_no_aux_rand(
            &Message::from_digest_slice(&hash[..]).unwrap(),
            &signing_key,
        ),
        sighash_type: hash_ty,
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
    let public_key = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret));
    let script = ScriptBuf::new_p2pk(&public_key);
    let funding = transaction(script.clone());
    let mut tx = transaction(ScriptBuf::new());
    tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
    let hash = SighashCache::new(&tx)
        .legacy_signature_hash(0, &script, hash_ty.to_u32())
        .unwrap();
    let signature = bitcoin::ecdsa::Signature {
        signature: secp.sign_ecdsa(&Message::from_digest_slice(&hash[..]).unwrap(), &secret),
        sighash_type: hash_ty,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].non_witness_utxo = Some(funding);
    psbt.inputs[0].partial_sigs.insert(public_key, signature);
    psbt
}

fn assert_mismatch(error: Error, required: u32, got: u32) {
    match error {
        Error::InputError(InputError::SighashMismatch { required: found, got: actual }, 0) => {
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
        let mut psbt = taproot_psbt(TapSighashType::Default, script_spend);
        psbt.inputs[0].sighash_type = Some(TapSighashType::Default.into());
        psbt.finalize_mut(&secp).unwrap();
        psbt.extract(&secp).unwrap();
        psbt.inputs[0].sighash_type = Some(TapSighashType::Default.into());
        psbt.finalize_mut(&secp).unwrap();
        psbt.extract(&secp).unwrap();
    }
}

#[test]
fn taproot_metadata_rejects_valid_none_signatures_before_mutation() {
    let secp = Secp256k1::verification_only();
    for &script_spend in &[false, true] {
        let partial = taproot_psbt(TapSighashType::None, script_spend);
        // Independently verify that these are valid transaction signatures.
        let finalized = partial.clone().finalize(&secp).unwrap();
        finalized.extract(&secp).unwrap();
        for mut psbt in vec![partial, finalized] {
            psbt.inputs[0].sighash_type = Some(TapSighashType::Default.into());
            assert_rejected_without_mutation(psbt, 0, TapSighashType::None as u32);
        }
    }
}

#[test]
fn absent_metadata_allows_valid_non_all_signatures() {
    let secp = Secp256k1::verification_only();
    for psbt in vec![
        taproot_psbt(TapSighashType::None, false),
        taproot_psbt(TapSighashType::None, true),
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
    let mut psbt = taproot_psbt(TapSighashType::Default, false);
    let script_psbt = taproot_psbt(TapSighashType::None, true);
    assert_eq!(psbt.unsigned_tx, script_psbt.unsigned_tx);
    psbt.inputs[0].tap_script_sigs = script_psbt.inputs[0].tap_script_sigs.clone();
    psbt.inputs[0].sighash_type = Some(TapSighashType::Default.into());
    assert_rejected_without_mutation(psbt, 0, 2);
}

#[test]
fn keypath_without_derivation_metadata_still_verifies_the_signature() {
    let secp = Secp256k1::verification_only();
    let mut psbt = taproot_psbt(TapSighashType::Default, false);
    assert!(psbt.inputs[0].tap_internal_key.is_none());
    assert!(psbt.inputs[0].tap_key_origins.is_empty());
    psbt.clone()
        .finalize(&secp)
        .unwrap()
        .extract(&secp)
        .unwrap();
    psbt.unsigned_tx.output[0].value -= bitcoin::Amount::ONE_SAT;
    let before = psbt.clone();
    assert!(psbt.finalize_mut(&secp).is_err());
    assert_eq!(psbt, before);
}
