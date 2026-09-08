extern crate bitcoin;
extern crate sapio_miniscript as miniscript;

use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::hashes::{hash160, hex::FromHex, Hash};
use bitcoin::PublicKey;
use miniscript::ord::Inscription;
use miniscript::policy::{Concrete, Semantic};
use miniscript::{Miniscript, Segwitv0, TranslatePk};
use std::str::FromStr;

const FIRST: &str = "0063036f726400016168";
const SECOND: &str = "0063036f726400016268";
const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

fn key(name: &str) -> Result<PublicKey, &'static str> {
    match name {
        "alice" => Ok(PublicKey::from_str(ALICE).unwrap()),
        "bob" => Ok(PublicKey::from_str(BOB).unwrap()),
        _ => Err("unknown key"),
    }
}

#[test]
fn nested_wrapper_translation_changes_keys_and_preserves_exact_envelopes() {
    let original = Miniscript::<String, Segwitv0>::from_str(&format!(
        "inscribe_pre({},inscribe_post({},and_v(v:pk(alice),pk(bob))))",
        FIRST, SECOND
    ))
    .unwrap();
    let mut visited = Vec::new();
    let translated: Miniscript<PublicKey, Segwitv0> = original
        .translate_pk(
            |name| {
                visited.push(name.clone());
                key(name)
            },
            |_| Err("unexpected key hash"),
        )
        .unwrap();
    assert_eq!(visited, vec!["alice", "bob"]);

    // Literal envelopes plus the independent Bitcoin script builder prevent
    // a matching mistake in Miniscript's serializer and parser from passing.
    let child = Builder::new()
        .push_key(&key("alice").unwrap())
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_key(&key("bob").unwrap())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    let mut expected = Vec::<u8>::from_hex(FIRST).unwrap();
    expected.extend_from_slice(child.as_bytes());
    expected.extend(Vec::<u8>::from_hex(SECOND).unwrap());
    assert_eq!(translated.encode().as_bytes(), expected);

    let rejected: Result<Miniscript<PublicKey, Segwitv0>, _> = original.translate_pk(
        |name| {
            if name == "bob" {
                Err("missing bob")
            } else {
                key(name)
            }
        },
        |_| Err("unexpected key hash"),
    );
    assert_eq!(rejected.unwrap_err(), "missing bob");
}

#[test]
fn policy_translation_reaches_keys_inside_nested_inscriptions() {
    let concrete = Concrete::<String>::from_str(&format!(
        "inscribe({},and(pk(alice),inscribe({},pk(bob))))",
        FIRST, SECOND
    ))
    .unwrap();
    let translated = concrete.translate_pk(|name| key(name)).unwrap();
    assert_eq!(
        translated.to_string(),
        format!(
            "inscribe({},and(pk({}),inscribe({},pk({}))))",
            FIRST, ALICE, SECOND, BOB
        )
    );
    let rejected: Result<Concrete<PublicKey>, _> = concrete.translate_pk(|name| {
        if name == "bob" {
            Err("missing bob")
        } else {
            key(name)
        }
    });
    assert_eq!(rejected.unwrap_err(), "missing bob");

    let semantic = Semantic::<String>::from_str(&format!(
        "inscribe({},and(pkh(alice),inscribe({},pkh(bob))))",
        FIRST, SECOND
    ))
    .unwrap();
    let key_hash = |name: &str| key(name).map(|key| hash160::Hash::hash(&key.to_bytes()));
    let translated: Semantic<PublicKey> = semantic.translate_pkh(|name| key_hash(name)).unwrap();
    assert_eq!(
        translated.to_string(),
        format!(
            "inscribe({},and(pkh({}),inscribe({},pkh({}))))",
            FIRST,
            key_hash("alice").unwrap(),
            SECOND,
            key_hash("bob").unwrap()
        )
    );
    let rejected: Result<Semantic<PublicKey>, _> = semantic.translate_pkh(|name| {
        if name == "bob" {
            Err("missing bob")
        } else {
            key_hash(name)
        }
    });
    assert_eq!(rejected.unwrap_err(), "missing bob");
}

#[test]
fn normalization_preserves_distinct_inscriptions_with_the_same_spending_key() {
    let first = Semantic::<String>::from_str(&format!("inscribe({},pkh(alice))", FIRST)).unwrap();
    let second = Semantic::<String>::from_str(&format!("inscribe({},pkh(alice))", SECOND)).unwrap();
    let alternatives = Semantic::Threshold(1, vec![first, second]);
    assert_eq!(alternatives.clone().normalized(), alternatives);
    let unreachable = Semantic::Inscribe(
        Box::new(Inscription::new(None, Some(b"unreachable".to_vec()))),
        Box::new(Semantic::Unsatisfiable),
    );
    assert_eq!(
        Semantic::Threshold(1, vec![alternatives.clone(), unreachable]).normalized(),
        alternatives
    );
}

#[test]
fn resource_limits_count_the_actual_envelope_bytes() {
    use miniscript::Terminal;
    use std::sync::Arc;

    let owner = key("alice").unwrap();
    let children = [
        (format!("pk({})", owner), 35),
        (
            format!("pkh({})", hash160::Hash::hash(&owner.to_bytes())),
            25,
        ),
    ];
    for (child, child_size) in &children {
        for script_size in &[3_600, 3_601] {
            // Seven body pushes need three length bytes apiece, in addition
            // to the empty envelope's eight bytes and the spending fragment.
            let body_size = script_size - 8 - 21 - child_size;
            let inscription = Inscription::new(None, Some(vec![b'a'; body_size]));
            let child = Miniscript::<PublicKey, Segwitv0>::from_str(child).unwrap();
            let candidate = Miniscript::from_ast(Terminal::InscribePre(
                Arc::new(vec![inscription]),
                Arc::new(child),
            ))
            .unwrap();
            assert_eq!(candidate.encode().len(), *script_size);
            assert_eq!(candidate.within_resource_limits(), *script_size == 3_600);
        }
    }
}

#[test]
#[cfg(feature = "compiler")]
fn compilation_respects_the_witness_script_size_limit() {
    use miniscript::policy::compiler::CompilerError;

    let policy = |body_size| {
        Concrete::Inscribe(
            Box::new(Inscription::new(None, Some(vec![b'a'; body_size]))),
            Box::new(Concrete::Key(key("alice").unwrap())),
        )
    };
    let compiled = policy(3_536).compile::<Segwitv0>().unwrap();
    assert_eq!(compiled.encode().len(), 3_600);
    compiled.sanity_check().unwrap();

    // Even the shorter P2PKH form needs 3,601 bytes for this body. Between
    // these cases the compiler may miss a viable P2PKH form, as documented
    // for LimitsExceeded; this does not require a complete compiler search.
    assert_eq!(
        policy(3_547).compile::<Segwitv0>().unwrap_err(),
        CompilerError::LimitsExceeded
    );
}
