extern crate bitcoin;
extern crate sapio_miniscript as miniscript;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Instruction;
use bitcoin::{PublicKey, Script};
use miniscript::ord::Inscription;
use miniscript::policy::{concrete::PolicyError, Concrete, Semantic};
use miniscript::{Miniscript, Segwitv0, Terminal};
use std::str::FromStr;
use std::sync::Arc;

type Ms = Miniscript<PublicKey, Segwitv0>;

fn key() -> PublicKey {
    PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .unwrap()
}

fn pk() -> Ms {
    Ms::from_str(&format!("pk({})", key())).unwrap()
}

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

fn counted_opcodes(script: &Script) -> usize {
    script
        .instructions()
        .filter(|instruction| match instruction {
            Ok(Instruction::Op(opcode)) => opcode.into_u8() > opcodes::all::OP_PUSHNUM_16.into_u8(),
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
            assert_eq!(ms.ext.ops_count_static, expected);
            assert_eq!(ms.ext.ops_count_sat, Some(expected));
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
            verified.ext.ops_count_sat,
            Some(counted_opcodes(&verified.encode()))
        );
    }
}

#[test]
fn inscriptions_preserve_impossible_paths_and_bound_postfix_stack_growth() {
    let yes = wrap(Ms::from_ast(Terminal::True).unwrap(), 1, true);
    assert_eq!(yes.ext.ops_count_nsat, None);
    assert_eq!(yes.ext.exec_stack_elem_count_dissat, None);
    assert_eq!(yes.ext.exec_stack_elem_count_sat, Some(2));
    let no = wrap(Ms::from_ast(Terminal::False).unwrap(), 1, true);
    assert_eq!(no.ext.ops_count_sat, None);
    assert_eq!(no.ext.exec_stack_elem_count_sat, None);
    assert_eq!(no.ext.exec_stack_elem_count_dissat, Some(2));
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
    let invalid = Concrete::<PublicKey>::Inscribe(
        Box::new(Inscription::default()),
        Box::new(Concrete::And(vec![])),
    );
    assert_eq!(invalid.is_valid(), Err(PolicyError::NonBinaryArgAnd));
    let duplicate = Concrete::Inscribe(
        Box::new(Inscription::default()),
        Box::new(Concrete::And(vec![
            Concrete::Key(key()),
            Concrete::Key(key()),
        ])),
    );
    assert_eq!(duplicate.keys(), vec![&key(), &key()]);
    assert_eq!(duplicate.is_valid(), Err(PolicyError::DuplicatePubKeys));

    let oversized = Inscription::new(Some(vec![1; 521]), None);
    let policy = Concrete::Inscribe(Box::new(oversized.clone()), Box::new(Concrete::Key(key())));
    assert!(policy.is_valid().is_err());
    assert!(Ms::from_ast(Terminal::InscribePre(
        Arc::new(vec![oversized]),
        Arc::new(pk())
    ))
    .is_err());
}

#[test]
fn singular_inscription_policy_parsers_preserve_the_displayed_policy() {
    let inscription = Inscription::new(Some(b"text/plain".to_vec()), Some(b"hello".to_vec()));
    let concrete = Concrete::<String>::Inscribe(
        Box::new(inscription.clone()),
        Box::new(Concrete::Key("alice".into())),
    );
    assert_eq!(
        Concrete::<String>::from_str(&concrete.to_string()).unwrap(),
        concrete
    );
    let semantic = Semantic::<String>::Inscribe(
        Box::new(inscription.clone()),
        Box::new(Semantic::KeyHash("alice".into())),
    );
    assert_eq!(
        Semantic::<String>::from_str(&semantic.to_string()).unwrap(),
        semantic
    );
    for encoded in &[
        String::new(),
        format!("{}{}", inscription, inscription),
        format!("{}51", inscription),
    ] {
        assert!(Concrete::<String>::from_str(&format!("inscribe({},pk(alice))", encoded)).is_err());
        assert!(
            Semantic::<String>::from_str(&format!("inscribe({},pkh(alice))", encoded)).is_err()
        );
    }
}

#[test]
fn inscription_semantics_recurse_without_discarding_reachable_metadata() {
    let inscription = Box::new(Inscription::default());
    let relative =
        Semantic::<String>::Inscribe(inscription.clone(), Box::new(Semantic::Older(100)));
    assert_eq!(relative.clone().at_age(99), Semantic::Unsatisfiable);
    assert_eq!(relative.clone().at_age(100), relative);
    let absolute =
        Semantic::<String>::Inscribe(inscription.clone(), Box::new(Semantic::After(100)));
    assert_eq!(absolute.clone().at_height(99), Semantic::Unsatisfiable);
    assert_eq!(absolute.clone().at_height(100), absolute);
    let child = Semantic::<String>::Threshold(
        1,
        vec![Semantic::Unsatisfiable, Semantic::KeyHash("a".into())],
    );
    assert_eq!(
        Semantic::Inscribe(inscription.clone(), Box::new(child)).normalized(),
        Semantic::Inscribe(inscription.clone(), Box::new(Semantic::KeyHash("a".into())))
    );
    let unordered = Semantic::<String>::Threshold(
        1,
        vec![Semantic::KeyHash("z".into()), Semantic::KeyHash("a".into())],
    );
    assert_eq!(
        Semantic::Inscribe(inscription.clone(), Box::new(unordered.clone())).sorted(),
        Semantic::Inscribe(inscription, Box::new(unordered.sorted()))
    );
}

#[test]
fn entailment_explicitly_rejects_unsupported_inscription_effects() {
    let child = Semantic::<String>::KeyHash("alice".into());
    let inscribed = Semantic::Inscribe(Box::new(Inscription::default()), Box::new(child.clone()));
    assert!(inscribed.clone().entails(child.clone()).is_err());
    assert!(child.clone().entails(inscribed.clone()).is_err());
    let nested = Semantic::Threshold(1, vec![inscribed, child.clone()]);
    assert!(nested.entails(child).is_err());
}
