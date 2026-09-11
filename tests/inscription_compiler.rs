#![cfg(feature = "compiler")]

extern crate bitcoin;

use std::sync::Arc;

use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::PublicKey;
use miniscript::ord::Inscription;
use miniscript::policy::{Concrete, Liftable};
use miniscript::{Miniscript, ScriptContext, Segwitv0, Tap, Terminal};

fn key(byte: u8) -> PublicKey {
    PublicKey::new(SecpPublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    ))
}

fn check_compilation<Ctx: ScriptContext>(child: Concrete<PublicKey>) {
    let inscription =
        Inscription::new(Some(b"text/plain".to_vec()), Some(b"compiled inscription".to_vec()));
    let policy = Concrete::Inscribe(Box::new(inscription.clone()), std::sync::Arc::new(child));
    let compiled = policy.compile::<Ctx>().unwrap();
    compiled.sanity_check().unwrap();
    assert_eq!(compiled.lift().unwrap().sorted(), policy.lift().unwrap().sorted());
    let embedded: Vec<_> = compiled
        .iter()
        .flat_map(|ms| match ms.node {
            Terminal::InscribePre(ref items, _) | Terminal::InscribePost(ref items, _) => {
                items.iter().collect::<Vec<_>>()
            }
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(embedded, vec![&inscription]);
    let script = compiled.encode();
    assert_eq!(
        Miniscript::<Ctx::Key, Ctx>::decode_with_ext(
            &script,
            &miniscript::ExtParams::sane().raw_pkh()
        )
        .unwrap()
        .encode(),
        script
    );
}

#[test]
fn inscription_compilation_preserves_compiled_child_conditions() {
    let owner = Concrete::Key(key(1));
    let alternative = Concrete::Or(vec![
        (9, Arc::new(owner.clone())),
        (1, Arc::new(Concrete::Key(key(2)))),
    ]);
    for child in &[owner, alternative] {
        check_compilation::<Segwitv0>(child.clone());
        check_compilation::<Tap>(child.clone());
    }
}
