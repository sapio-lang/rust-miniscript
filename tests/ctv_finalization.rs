extern crate bitcoin;
extern crate sapio_miniscript as miniscript;

use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::util::sighash::{SchnorrSighashType, SighashCache};
use bitcoin::util::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{EcdsaSig, EcdsaSighashType, OutPoint, PublicKey, Script, Transaction, TxIn, TxOut};
use miniscript::psbt::{interpreter_check, Error, InputError, PsbtExt};
use miniscript::{Miniscript, Segwitv0};
use std::str::FromStr;

#[derive(Clone, Copy)]
enum CtvOutput {
    Wsh,
    Taproot,
    NestedWsh,
}

fn public_key() -> PublicKey {
    PublicKey::new(SecpPublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[1; 32]).unwrap(),
    ))
}

fn funding_transaction(script_pubkey: Script) -> Transaction {
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

fn legacy_signature(tx: &Transaction, index: usize, nonce: u8) -> EcdsaSig {
    let hash_ty = EcdsaSighashType::NonePlusAnyoneCanPay;
    let hash = SighashCache::new(tx)
        .legacy_signature_hash(index, &Script::new_p2pk(&public_key()), hash_ty.to_u32())
        .unwrap();
    EcdsaSig {
        sig: Secp256k1::new().sign_ecdsa_with_noncedata(
            &Message::from_digest_slice(&hash[..]).unwrap(),
            &SecretKey::from_slice(&[1; 32]).unwrap(),
            &[nonce; 32],
        ),
        hash_ty,
    }
}

fn signature_script(signature: EcdsaSig) -> Script {
    Builder::new().push_slice(&signature.to_vec()).into_script()
}

// Construct fixture commitments from the BIP-119 serialized fields, without
// calling the implementation being tested. The hash corpus tests separately
// verify these fields against the official expected hashes.
fn template_hash(tx: &Transaction, index: usize) -> sha256::Hash {
    let mut fields = serialize(&tx.version);
    fields.extend(serialize(&tx.lock_time));
    if tx.input.iter().any(|input| !input.script_sig.is_empty()) {
        let mut scripts = Vec::new();
        for input in &tx.input {
            scripts.extend(serialize(&input.script_sig));
        }
        fields.extend_from_slice(&sha256::Hash::hash(&scripts)[..]);
    }
    fields.extend(serialize(&(tx.input.len() as u32)));
    let mut sequences = Vec::new();
    for input in &tx.input {
        sequences.extend(serialize(&input.sequence));
    }
    fields.extend_from_slice(&sha256::Hash::hash(&sequences)[..]);
    fields.extend(serialize(&(tx.output.len() as u32)));
    let mut outputs = Vec::new();
    for output in &tx.output {
        outputs.extend(serialize(output));
    }
    fields.extend_from_slice(&sha256::Hash::hash(&outputs)[..]);
    fields.extend(serialize(&(index as u32)));
    sha256::Hash::hash(&fields)
}

fn mixed_psbt(ctv_index: usize, kind: CtvOutput, commit_legacy_script: bool) -> (Psbt, Script) {
    let legacy_index = 1 - ctv_index;
    let legacy_funding = funding_transaction(Script::new_p2pk(&public_key()));
    let mut tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn::default(), TxIn::default()],
        output: vec![TxOut {
            value: 19_000,
            script_pubkey: Script::new_p2pk(&public_key()),
        }],
    };
    tx.input[legacy_index].previous_output = OutPoint::new(legacy_funding.txid(), 0);
    for input in &mut tx.input {
        input.sequence = 0xfffffffd;
    }

    // NONE|ANYONECANPAY makes the exact legacy scriptSig independent of the
    // CTV input and outputs, so constructing its commitment has no hash cycle.
    let signature = legacy_signature(&tx, legacy_index, 0);
    let legacy_script = signature_script(signature);
    let mut template = tx.clone();
    if commit_legacy_script {
        template.input[legacy_index].script_sig = legacy_script.clone();
    }
    let hash = template_hash(&template, ctv_index);
    let script = Miniscript::<PublicKey, Segwitv0>::from_str(&format!("t:txtmpl({})", hash))
        .unwrap()
        .encode();
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let ctv_spk = match kind {
        CtvOutput::Wsh => {
            psbt.inputs[ctv_index].witness_script = Some(script.clone());
            script.to_v0_p2wsh()
        }
        CtvOutput::NestedWsh => {
            let redeem_script = script.to_v0_p2wsh();
            psbt.inputs[ctv_index].witness_script = Some(script.clone());
            psbt.inputs[ctv_index].redeem_script = Some(redeem_script.clone());
            redeem_script.to_p2sh()
        }
        CtvOutput::Taproot => {
            psbt.inputs[ctv_index].sighash_type = Some(SchnorrSighashType::Default.into());
            let secp = Secp256k1::new();
            let internal_key = public_key().inner.x_only_public_key().0;
            let spend_info = TaprootBuilder::new()
                .add_leaf(0, script.clone())
                .unwrap()
                .finalize(&secp, internal_key)
                .unwrap();
            let leaf = (script, LeafVersion::TapScript);
            let control_block = spend_info.control_block(&leaf).unwrap();
            psbt.inputs[ctv_index]
                .tap_scripts
                .insert(control_block, leaf);
            Script::new_v1_p2tr_tweaked(spend_info.output_key())
        }
    };
    let ctv_funding = funding_transaction(ctv_spk);
    psbt.unsigned_tx.input[ctv_index].previous_output = OutPoint::new(ctv_funding.txid(), 0);
    psbt.inputs[ctv_index].witness_utxo = Some(ctv_funding.output[0].clone());
    psbt.inputs[ctv_index].non_witness_utxo = Some(ctv_funding);
    psbt.inputs[legacy_index].non_witness_utxo = Some(legacy_funding);
    psbt.inputs[legacy_index]
        .partial_sigs
        .insert(public_key(), signature);
    psbt.inputs[legacy_index].sighash_type = Some(signature.hash_ty.into());
    (psbt, legacy_script)
}

fn set_final_legacy(psbt: &mut Psbt, index: usize, script: Script) {
    psbt.inputs[index].final_script_sig = Some(script);
    psbt.inputs[index].partial_sigs.clear();
    psbt.inputs[index].sighash_type = None;
}

fn assert_ctv_error(error: Error, index: usize) {
    match error {
        Error::InputError(
            InputError::Interpreter(miniscript::interpreter::Error::TxTemplateHashWrong),
            input,
        ) => {
            assert_eq!(input, index);
        }
        other => panic!("expected CTV mismatch at input {}, got {:?}", index, other),
    }
}

#[test]
fn native_ctv_finalizes_after_legacy_inputs_in_either_order() {
    let secp = Secp256k1::verification_only();
    for &kind in &[CtvOutput::Wsh, CtvOutput::Taproot] {
        for ctv_index in 0..2 {
            for &allow_mall in &[false, true] {
                let (mut psbt, legacy_script) = mixed_psbt(ctv_index, kind, true);
                if allow_mall {
                    psbt.finalize_mall_mut(&secp).unwrap();
                } else {
                    psbt.finalize_mut(&secp).unwrap();
                }
                let tx = psbt.extract(&secp).unwrap();
                assert_eq!(tx.input[1 - ctv_index].script_sig, legacy_script);
                assert!(tx.input[ctv_index].script_sig.is_empty());
                assert!(!tx.input[ctv_index].witness.is_empty());
            }
        }
    }
}

#[test]
fn native_ctv_accepts_fixed_final_legacy_scriptsigs() {
    let secp = Secp256k1::verification_only();
    for &kind in &[CtvOutput::Wsh, CtvOutput::Taproot] {
        for ctv_index in 0..2 {
            let (mut psbt, legacy_script) = mixed_psbt(ctv_index, kind, true);
            set_final_legacy(&mut psbt, 1 - ctv_index, legacy_script.clone());
            let mut finalized = psbt.finalize(&secp).unwrap();
            assert_eq!(
                finalized.extract(&secp).unwrap().input[1 - ctv_index].script_sig,
                legacy_script
            );
            let before = finalized.clone();
            finalized.finalize_mut(&secp).unwrap();
            assert_eq!(finalized, before);
        }
    }
}

#[test]
fn single_input_ctv_waits_for_the_committed_legacy_scriptsig() {
    let secp = Secp256k1::verification_only();
    for &kind in &[CtvOutput::Wsh, CtvOutput::Taproot] {
        let (mut psbt, _) = mixed_psbt(0, kind, true);
        let before = psbt.clone();
        assert!(psbt.finalize_inp_mut(&secp, 0).is_err());
        assert_eq!(psbt, before);
        psbt.finalize_inp_mut(&secp, 1).unwrap();
        psbt.finalize_inp_mut(&secp, 0).unwrap();
        psbt.extract(&secp).unwrap();
    }
}

#[test]
fn later_legacy_scriptsig_invalidates_an_empty_commitment() {
    let secp = Secp256k1::verification_only();
    for &kind in &[CtvOutput::Wsh, CtvOutput::Taproot] {
        let (mut psbt, legacy_script) = mixed_psbt(0, kind, false);
        // An individual input check is valid against the current partial PSBT.
        // Whole-transaction finalization must reject it after the legacy input
        // supplies the scriptSig that the CTV branch did not commit to.
        psbt.finalize_inp_mut(&secp, 0).unwrap();
        assert!(psbt.finalize_mut(&secp).is_err());
        assert_eq!(
            psbt.inputs[1].final_script_sig.as_ref(),
            Some(&legacy_script)
        );
        assert_ctv_error(interpreter_check(&psbt, &secp).unwrap_err(), 0);
        assert_ctv_error(psbt.extract(&secp).unwrap_err(), 0);
    }
}

#[test]
fn current_candidate_scriptsig_is_included_in_ctv_interpretation() {
    let secp = Secp256k1::verification_only();
    let (mut psbt, legacy_script) = mixed_psbt(0, CtvOutput::NestedWsh, true);
    set_final_legacy(&mut psbt, 1, legacy_script);
    let before = psbt.clone();
    // The commitment includes the legacy input but omits this input's redeem
    // program. Satisfying the nested witness output supplies that scriptSig,
    // which must invalidate CTV before the candidate is written to the PSBT.
    assert_ctv_error(psbt.finalize_inp_mut(&secp, 0).unwrap_err(), 0);
    assert_eq!(psbt, before);
}

#[test]
fn completed_ctv_rejects_changed_outputs_and_valid_legacy_signatures() {
    let secp = Secp256k1::verification_only();
    for &kind in &[CtvOutput::Wsh, CtvOutput::Taproot] {
        let (mut psbt, _) = mixed_psbt(0, kind, true);
        psbt.finalize_mut(&secp).unwrap();

        let mut changed_output = psbt.clone();
        changed_output.unsigned_tx.output[0].value -= 1;
        assert_ctv_error(interpreter_check(&changed_output, &secp).unwrap_err(), 0);
        assert_ctv_error(changed_output.extract(&secp).unwrap_err(), 0);

        let mut changed_script = psbt;
        let replacement = signature_script(legacy_signature(&changed_script.unsigned_tx, 1, 1));
        assert_ne!(
            changed_script.inputs[1].final_script_sig.as_ref(),
            Some(&replacement)
        );
        changed_script.inputs[1].final_script_sig = Some(replacement);
        // A different valid ECDSA nonce preserves the legacy signature check;
        // only the exact-scriptSig CTV commitment forbids this replacement.
        changed_script.finalize_inp_mut(&secp, 1).unwrap();
        assert_ctv_error(interpreter_check(&changed_script, &secp).unwrap_err(), 0);
        assert_ctv_error(changed_script.extract(&secp).unwrap_err(), 0);
    }
}

fn assert_public_checks_reject(psbt: Psbt) {
    let secp = Secp256k1::verification_only();
    assert!(psbt.clone().finalize_mut(&secp).is_err());
    assert!(psbt.clone().finalize_mall_mut(&secp).is_err());
    let mut single = psbt.clone();
    assert!(single.finalize_inp_mut(&secp, 0).is_err());
    assert_eq!(single, psbt);
    assert!(single.finalize_inp_mall_mut(&secp, 0).is_err());
    assert_eq!(single, psbt);
    assert!(interpreter_check(&psbt, &secp).is_err());
    assert!(psbt.extract(&secp).is_err());
}

#[test]
fn malformed_psbt_shapes_are_rejected_by_public_checks() {
    let (psbt, _) = mixed_psbt(0, CtvOutput::Wsh, true);
    let mut no_inputs = psbt.clone();
    no_inputs.unsigned_tx.input.clear();
    no_inputs.inputs.clear();
    assert_public_checks_reject(no_inputs);
    let mut missing_input = psbt.clone();
    missing_input.inputs.pop();
    assert_public_checks_reject(missing_input);
    let mut extra_input = psbt.clone();
    extra_input.unsigned_tx.input.pop();
    assert_public_checks_reject(extra_input);
    let mut missing_output = psbt.clone();
    missing_output.outputs.pop();
    assert_public_checks_reject(missing_output);
    let mut signed_unsigned_tx = psbt.clone();
    signed_unsigned_tx.unsigned_tx.input[0].script_sig = Builder::new().push_int(1).into_script();
    assert_public_checks_reject(signed_unsigned_tx);
    let mut witnessed_unsigned_tx = psbt;
    witnessed_unsigned_tx.unsigned_tx.input[0]
        .witness
        .push(&[1]);
    assert_public_checks_reject(witnessed_unsigned_tx);
}

#[test]
fn invalid_non_witness_prevout_index_is_rejected_without_panicking() {
    let (mut psbt, _) = mixed_psbt(0, CtvOutput::Wsh, true);
    psbt.unsigned_tx.input[1].previous_output.vout = 1;
    assert_public_checks_reject(psbt);
}

#[test]
fn single_input_malleable_finalization_allows_available_hashlock_branches() {
    let secp = Secp256k1::verification_only();
    let first = [1; 32];
    let second = [2; 32];
    let first_hash = sha256::Hash::hash(&first);
    let second_hash = sha256::Hash::hash(&second);
    let script = Miniscript::<PublicKey, Segwitv0>::from_str_insane(&format!(
        "or_i(sha256({}),sha256({}))",
        first_hash, second_hash
    ))
    .unwrap()
    .encode();
    let funding = funding_transaction(script.to_v0_p2wsh());
    let mut tx = funding_transaction(Script::new_p2pk(&public_key()));
    tx.input[0].previous_output = OutPoint::new(funding.txid(), 0);
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
    psbt.inputs[0].witness_script = Some(script);
    psbt.inputs[0]
        .sha256_preimages
        .insert(first_hash, first.to_vec());
    psbt.inputs[0]
        .sha256_preimages
        .insert(second_hash, second.to_vec());
    assert!(psbt.finalize_inp_mut(&secp, 0).is_err());
    psbt.finalize_inp_mall_mut(&secp, 0).unwrap();
    psbt.extract(&secp).unwrap();
}
