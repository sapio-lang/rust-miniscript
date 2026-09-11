extern crate bitcoin;

use std::str::FromStr;
use std::sync::Arc;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, Signature, TapLeafHash, TaprootBuilder};
use bitcoin::{
    absolute, relative, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use miniscript::interpreter::Interpreter;
use miniscript::ord::Inscription;
use miniscript::policy::concrete::PolicyError;
use miniscript::policy::{Concrete, Semantic};
use miniscript::psbt::{interpreter_check, PsbtExt};
use miniscript::{AbsLockTime, Miniscript, RelLockTime, Segwitv0, Tap, Terminal, Threshold};

type Ms = Miniscript<PublicKey, Segwitv0>;

fn key() -> PublicKey {
    PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .unwrap()
}

fn pk() -> Ms { Ms::from_str(&format!("pk({})", key())).unwrap() }

fn wrap(child: Ms, count: usize, postfix: bool) -> Ms {
    let inscriptions = Arc::new(vec![Inscription::default(); count]);
    let child = Arc::new(child);
    Ms::from_ast(if postfix {
        Terminal::InscribePost(inscriptions, child)
    } else {
        Terminal::InscribePre(inscriptions, child)
    })
    .unwrap()
}

fn counted_opcodes(script: &bitcoin::Script) -> usize {
    script
        .instructions()
        .filter(|instruction| match instruction {
            Ok(Instruction::Op(opcode)) => opcode.to_u8() > opcodes::all::OP_PUSHNUM_16.to_u8(),
            _ => false,
        })
        .count()
}

#[test]
fn inscription_opcode_accounting_matches_the_legacy_consensus_limit() {
    for &postfix in &[false, true] {
        for count in &[100, 101] {
            let ms = wrap(pk(), *count, postfix);
            let expected = 2 * count + 1;
            assert_eq!(counted_opcodes(&ms.encode()), expected);
            assert_eq!(ms.ext.static_ops, expected);
            assert_eq!(
                ms.ext
                    .sat_data
                    .map(|data| ms.ext.static_ops + data.max_exec_op_count),
                Some(expected)
            );
            assert_eq!(ms.within_resource_limits(), *count == 100);
        }
    }
}

#[test]
fn postfix_verify_accounts_for_the_opcode_after_endif() {
    for &postfix in &[false, true] {
        let wrapped = wrap(pk(), 1, postfix);
        assert_eq!(wrapped.ext.has_free_verify, !postfix);
        let verified = Ms::from_ast(Terminal::Verify(Arc::new(wrapped))).unwrap();
        assert_eq!(verified.script_size(), verified.encode().len());
        assert_eq!(verified.ext.pk_cost, verified.encode().len());
        assert_eq!(
            verified
                .ext
                .sat_data
                .map(|data| verified.ext.static_ops + data.max_exec_op_count),
            Some(counted_opcodes(&verified.encode()))
        );
    }
}

#[test]
fn inscriptions_preserve_impossible_paths_and_bound_postfix_stack_growth() {
    let yes = wrap(Ms::from_ast(Terminal::True).unwrap(), 1, true);
    assert_eq!(
        yes.ext
            .dissat_data
            .map(|data| yes.ext.static_ops + data.max_exec_op_count),
        None
    );
    assert_eq!(yes.ext.dissat_data.map(|data| data.max_exec_stack_count), None);
    assert_eq!(yes.ext.sat_data.map(|data| data.max_exec_stack_count), Some(2));
    let no = wrap(Ms::from_ast(Terminal::False).unwrap(), 1, true);
    assert_eq!(
        no.ext
            .sat_data
            .map(|data| no.ext.static_ops + data.max_exec_op_count),
        None
    );
    assert_eq!(no.ext.sat_data.map(|data| data.max_exec_stack_count), None);
    assert_eq!(no.ext.dissat_data.map(|data| data.max_exec_stack_count), Some(2));
    for &postfix in &[false, true] {
        let inscriptions = Arc::new(vec![]);
        let child = Arc::new(pk());
        let empty = if postfix {
            Terminal::InscribePost(inscriptions, child)
        } else {
            Terminal::InscribePre(inscriptions, child)
        };
        assert!(Ms::from_ast(empty).is_err());
    }
}

#[test]
fn inscription_children_remain_visible_to_key_analysis() {
    let duplicate = Ms::from_str_insane(&format!("and_v(v:pk({}),pk({}))", key(), key())).unwrap();
    for &postfix in &[false, true] {
        let wrapped = wrap(duplicate.clone(), 1, postfix);
        assert_eq!(wrapped.branches().len(), 1);
        assert!(wrapped.get_nth_child(0).is_some());
        assert!(wrapped.get_nth_child(1).is_none());
        assert_eq!(wrapped.iter_pk().count(), 2);
        assert!(wrapped.has_repeated_keys());
        assert!(wrapped.sanity_check().is_err());
    }
}

#[test]
fn inscription_policies_validate_their_child_and_push_sizes() {
    let invalid = Concrete::<PublicKey>::Inscribe(Box::default(), Arc::new(Concrete::And(vec![])));
    #[cfg(feature = "compiler")]
    assert!(matches!(
        invalid.compile::<Segwitv0>(),
        Err(miniscript::policy::compiler::CompilerError::NonBinaryArgAnd)
    ));
    #[cfg(not(feature = "compiler"))]
    let _ = invalid;
    let duplicate = Concrete::Inscribe(
        Box::default(),
        Arc::new(Concrete::And(vec![Concrete::Key(key()).into(), Concrete::Key(key()).into()])),
    );
    assert_eq!(duplicate.keys(), vec![&key(), &key()]);
    assert_eq!(duplicate.is_valid(), Err(PolicyError::DuplicatePubKeys));

    let oversized = Inscription::new(Some(vec![1; 521]), None);
    let policy = Concrete::Inscribe(Box::new(oversized.clone()), Arc::new(Concrete::Key(key())));
    assert!(policy.is_valid().is_err());
    assert!(Ms::from_ast(Terminal::InscribePre(Arc::new(vec![oversized]), Arc::new(pk()))).is_err());
}

#[test]
fn singular_inscription_policy_parsers_preserve_the_displayed_policy() {
    let inscription = Inscription::new(Some(b"text/plain".to_vec()), Some(b"hello".to_vec()));
    let concrete = Concrete::<String>::Inscribe(
        Box::new(inscription.clone()),
        Arc::new(Concrete::Key("alice".into())),
    );
    assert_eq!(Concrete::<String>::from_str(&concrete.to_string()).unwrap(), concrete);
    let semantic = Semantic::<String>::Inscribe(
        Box::new(inscription.clone()),
        Arc::new(Semantic::Key("alice".into())),
    );
    assert_eq!(Semantic::<String>::from_str(&semantic.to_string()).unwrap(), semantic);
    for encoded in &[
        String::new(),
        format!("{}{}", inscription, inscription),
        format!("{}51", inscription),
    ] {
        assert!(Concrete::<String>::from_str(&format!("inscribe({},pk(alice))", encoded)).is_err());
        assert!(Semantic::<String>::from_str(&format!("inscribe({},pk(alice))", encoded)).is_err());
    }
}

#[test]
fn inscription_semantics_recurse_without_discarding_reachable_metadata() {
    let inscription = Box::new(Inscription::default());
    let relative = Semantic::<String>::Inscribe(
        inscription.clone(),
        Arc::new(Semantic::Older(RelLockTime::from_consensus(100).unwrap())),
    );
    assert_eq!(
        relative.clone().at_age(relative::LockTime::from_height(99)),
        Semantic::Unsatisfiable
    );
    assert_eq!(
        relative
            .clone()
            .at_age(relative::LockTime::from_height(100)),
        relative
    );
    let absolute = Semantic::<String>::Inscribe(
        inscription.clone(),
        Arc::new(Semantic::After(AbsLockTime::from_consensus(100).unwrap())),
    );
    assert_eq!(
        absolute
            .clone()
            .at_lock_time(absolute::LockTime::from_consensus(99)),
        Semantic::Unsatisfiable
    );
    assert_eq!(
        absolute
            .clone()
            .at_lock_time(absolute::LockTime::from_consensus(100)),
        absolute
    );
    let child = Semantic::<String>::Thresh(
        Threshold::new(
            1,
            vec![
                Semantic::Unsatisfiable.into(),
                Semantic::Key("a".into()).into(),
            ],
        )
        .unwrap(),
    );
    assert_eq!(
        Semantic::Inscribe(inscription.clone(), Arc::new(child)).normalized(),
        Semantic::Inscribe(inscription.clone(), Arc::new(Semantic::Key("a".into())))
    );
    let unordered = Semantic::<String>::Thresh(
        Threshold::new(
            1,
            vec![
                Semantic::Key("z".into()).into(),
                Semantic::Key("a".into()).into(),
            ],
        )
        .unwrap(),
    );
    assert_eq!(
        Semantic::Inscribe(inscription.clone(), Arc::new(unordered.clone())).sorted(),
        Semantic::Inscribe(inscription, Arc::new(unordered.sorted()))
    );
}

#[test]
fn entailment_explicitly_rejects_unsupported_inscription_effects() {
    let child = Semantic::<String>::Key("alice".into());
    let inscribed = Semantic::Inscribe(Box::default(), Arc::new(child.clone()));
    assert!(inscribed.clone().entails(child.clone()).is_none());
    assert!(child.clone().entails(inscribed.clone()).is_none());
    let nested =
        Semantic::Thresh(Threshold::new(1, vec![inscribed.into(), child.clone().into()]).unwrap());
    assert!(nested.entails(child).is_none());
}

#[test]
fn interpreter_checks_the_condition_inside_an_inscription() {
    for &postfix in &[false, true] {
        for &satisfied in &[false, true] {
            let child = Ms::from_ast(if satisfied {
                Terminal::True
            } else {
                Terminal::False
            })
            .unwrap();
            let script = wrap(child, 1, postfix).encode();
            let spk = script.to_p2wsh();
            let script_sig = ScriptBuf::new();
            let witness = Witness::from_slice(&[script.into_bytes()]);
            let interpreter = Interpreter::from_txdata(
                &spk,
                &script_sig,
                &witness,
                Sequence::ZERO,
                absolute::LockTime::ZERO,
            )
            .unwrap();
            let result = interpreter
                .iter_assume_sigs()
                .collect::<Result<Vec<_>, _>>();
            assert_eq!(result.is_ok(), satisfied);
        }
    }
}

#[test]
fn signed_taproot_inscriptions_finalize_and_reject_invalid_signatures() {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
    let public_key = keypair.x_only_public_key().0;
    for &postfix in &[false, true] {
        let child = Arc::new(
            Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!("pk({})", public_key)).unwrap(),
        );
        let inscriptions = Arc::new(vec![Inscription::new(
            Some(b"text/plain".to_vec()),
            Some(b"signed inscription".to_vec()),
        )]);
        let script = Miniscript::from_ast(if postfix {
            Terminal::InscribePost(inscriptions, child)
        } else {
            Terminal::InscribePre(inscriptions, child)
        })
        .unwrap()
        .encode();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&secp, public_key)
            .unwrap();
        let funding = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            }],
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut { value: Amount::from_sat(9_000), script_pubkey: ScriptBuf::new() }],
        };
        tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        let leaf = (script.clone(), LeafVersion::TapScript);
        let leaf_hash = TapLeafHash::from_script(&leaf.0, leaf.1);
        let hash_ty = TapSighashType::Default;
        let hash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&funding.output),
                leaf_hash,
                hash_ty,
            )
            .unwrap();
        let signature = Signature {
            signature: secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &keypair),
            sighash_type: hash_ty,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
        psbt.inputs[0].sighash_type = Some(hash_ty.into());
        psbt.inputs[0]
            .tap_scripts
            .insert(spend_info.control_block(&leaf).unwrap(), leaf);
        psbt.inputs[0]
            .tap_script_sigs
            .insert((public_key, leaf_hash), signature);

        // This signature is well formed but commits to a different message.
        let invalid_signature = Signature {
            signature: secp.sign_schnorr_no_aux_rand(&Message::from_digest([0; 32]), &keypair),
            sighash_type: hash_ty,
        };
        let mut invalid = psbt.clone();
        invalid.inputs[0]
            .tap_script_sigs
            .insert((public_key, leaf_hash), invalid_signature);
        assert!(invalid.finalize_mut(&secp).is_err());

        psbt.finalize_mut(&secp).unwrap();
        interpreter_check(&psbt, &secp).unwrap();
        let extracted = psbt.extract(&secp).unwrap();
        let witness = extracted.input[0].witness.to_vec();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[1], script.as_bytes());

        let mut corrupted = witness;
        corrupted[0] = invalid_signature.to_vec();
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&corrupted));
        assert!(interpreter_check(&psbt, &secp).is_err());
        assert!(psbt.extract(&secp).is_err());
    }
}
