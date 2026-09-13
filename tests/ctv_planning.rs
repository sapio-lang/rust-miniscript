//! Selected native CTV commitments must follow the witness, not provider queries.

use std::cell::Cell;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{PublicKey, XOnlyPublicKey};
use miniscript::miniscript::satisfy::Witness;
use miniscript::plan::AssetProvider;
use miniscript::{DefiniteDescriptorKey, Descriptor, Miniscript, Satisfier, Tap, ToPublicKey};

fn key(seed: u8) -> XOnlyPublicKey {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[seed; 32]).unwrap())
        .x_only_public_key()
        .0
}

fn hash(seed: u8) -> sha256::Hash { sha256::Hash::hash(&[seed]) }

struct Assets {
    template: Option<sha256::Hash>,
    all_templates: bool,
    key_path: bool,
}

impl Assets {
    fn fixed(template: Option<sha256::Hash>) -> Self {
        Self { template, all_templates: false, key_path: false }
    }
}

macro_rules! impl_assets {
    ($key:ty) => {
        impl AssetProvider<$key> for Assets {
            fn provider_lookup_ecdsa_sig(&self, _: &$key) -> bool { true }
            fn provider_lookup_tap_leaf_script_sig(
                &self,
                _: &$key,
                _: &TapLeafHash,
            ) -> Option<usize> {
                Some(65)
            }
            fn provider_lookup_tap_key_spend_sig(&self, _: &$key) -> Option<usize> {
                if self.key_path {
                    Some(65)
                } else {
                    None
                }
            }
            fn check_tx_template(&self, hash: sha256::Hash) -> bool {
                self.all_templates || self.template == Some(hash)
            }
        }
    };
}
impl_assets!(XOnlyPublicKey);
impl_assets!(DefiniteDescriptorKey);

#[test]
fn selected_alternative_keeps_only_its_own_commitment() {
    let script = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!(
        "or_i(and_v(txtmpl({}),pk({})),and_v(txtmpl({}),pk({})))",
        hash(1),
        key(1),
        hash(2),
        key(2)
    ))
    .unwrap();
    for selected in [hash(1), hash(2)] {
        let assets = Assets::fixed(Some(selected));
        for plan in [
            script.build_template(&assets),
            script.build_template_mall(&assets),
        ] {
            assert!(matches!(plan.stack, Witness::Stack(_)));
            assert_eq!(plan.tx_template, Some(selected));
        }
    }
    let free = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!(
        "or_i(and_v(txtmpl({}),pk({})),pk({}))",
        hash(1),
        key(1),
        key(2)
    ))
    .unwrap()
    .build_template(&Assets::fixed(None));
    assert!(matches!(free.stack, Witness::Stack(_)));
    assert_eq!(free.tx_template, None);
}

#[test]
fn duplicate_commitments_merge_and_distinct_conjunctions_are_impossible() {
    let all = Assets { all_templates: true, ..Assets::fixed(None) };
    for second in [hash(1), hash(2)] {
        let script = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!(
            "and_v(txtmpl({}),and_v(txtmpl({}),pk({})))",
            hash(1),
            second,
            key(1)
        ))
        .unwrap();
        for plan in [
            script.build_template(&all),
            script.build_template_mall(&all),
        ] {
            if second == hash(1) {
                assert!(matches!(plan.stack, Witness::Stack(_)));
                assert_eq!(plan.tx_template, Some(hash(1)));
            } else {
                assert_eq!(plan.stack, Witness::Impossible);
            }
        }
    }
}

#[test]
fn a_fixed_commitment_pass_recovers_the_compatible_outer_and_alternative() {
    // The right branch of or_i has a cheaper selector. Accepting both hashes
    // would greedily choose it before discovering the outer A constraint.
    let script = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!(
        "and_v(v:or_i(and_v(txtmpl({}),pk({})),and_v(txtmpl({}),pk({}))),t:txtmpl({}))",
        hash(1),
        key(1),
        hash(2),
        key(2),
        hash(1)
    ))
    .unwrap();
    let all = Assets { all_templates: true, ..Assets::fixed(None) };
    assert_eq!(script.build_template(&all).stack, Witness::Impossible);
    assert_eq!(script.build_template_mall(&all).stack, Witness::Impossible);
    for assets in [Assets::fixed(Some(hash(1))), Assets::fixed(Some(hash(2)))] {
        for plan in [
            script.build_template(&assets),
            script.build_template_mall(&assets),
        ] {
            if assets.template == Some(hash(1)) {
                assert!(matches!(plan.stack, Witness::Stack(_)));
                assert_eq!(plan.tx_template, Some(hash(1)));
            } else {
                assert_eq!(plan.stack, Witness::Impossible);
            }
        }
    }
}

#[test]
fn thresholds_and_wrappers_keep_only_executed_commitments() {
    for (expression, expected) in [
        (format!("and_v(vd:txtmpl({}),pk({}))", hash(1), key(1)), Some(hash(1))),
        (
            format!(
                "thresh(2,or_i(and_v(txtmpl({}),pk({})),0),s:pk({}),a:0)",
                hash(1),
                key(1),
                key(2)
            ),
            Some(hash(1)),
        ),
        // The unused CTV arm is dissatisfied through its CTV-free false branch.
        (
            format!("or_b(or_i(and_v(txtmpl({}),pk({})),0),s:pk({}))", hash(1), key(1), key(2)),
            None,
        ),
        (
            format!("thresh(1,or_i(and_v(txtmpl({}),pk({})),0),s:pk({}))", hash(1), key(1), key(2)),
            None,
        ),
    ] {
        let script = Miniscript::<XOnlyPublicKey, Tap>::from_str(&expression).unwrap();
        for plan in [
            script.build_template(&Assets::fixed(Some(hash(1)))),
            script.build_template_mall(&Assets::fixed(Some(hash(1)))),
        ] {
            assert!(matches!(plan.stack, Witness::Stack(_)), "{}", expression);
            assert_eq!(plan.tx_template, expected, "{}", expression);
        }
    }
    let all = Assets { all_templates: true, ..Assets::fixed(None) };
    let conflicting = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!(
        "thresh(2,or_i(and_v(txtmpl({}),pk({})),0),a:or_i(and_v(txtmpl({}),pk({})),0))",
        hash(1),
        key(1),
        hash(2),
        key(2)
    ))
    .unwrap();
    assert_eq!(conflicting.build_template(&all).stack, Witness::Impossible);
    assert_eq!(conflicting.build_template_mall(&all).stack, Witness::Impossible);
}

struct Complete {
    template: Option<sha256::Hash>,
    signatures_requested: Cell<usize>,
}

impl<Pk: ToPublicKey> Satisfier<Pk> for Complete {
    fn check_tx_template(&self, hash: sha256::Hash) -> bool { self.template == Some(hash) }
    fn lookup_ecdsa_sig(&self, _: &Pk) -> Option<bitcoin::ecdsa::Signature> {
        self.signatures_requested
            .set(self.signatures_requested.get() + 1);
        None
    }
    fn lookup_tap_leaf_script_sig(
        &self,
        _: &Pk,
        _: &TapLeafHash,
    ) -> Option<bitcoin::taproot::Signature> {
        self.signatures_requested
            .set(self.signatures_requested.get() + 1);
        let pair =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[1; 32]).unwrap());
        Some(bitcoin::taproot::Signature {
            signature: Secp256k1::new()
                .sign_schnorr_no_aux_rand(&Message::from_digest([0; 32]), &pair),
            sighash_type: bitcoin::TapSighashType::All,
        })
    }
}

#[test]
fn descriptor_plans_expose_the_selected_hash_and_completion_rechecks_it_first() {
    let public = PublicKey::new(
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[1; 32]).unwrap())
            .public_key(),
    );
    for expression in [
        format!("wsh(and_v(txtmpl({}),pk({})))", hash(1), public),
        format!("sh(wsh(and_v(txtmpl({}),pk({}))))", hash(1), public),
        format!("sh(and_v(txtmpl({}),pk({})))", hash(1), public),
        format!("tr({},and_v(txtmpl({}),pk({})))", key(2), hash(1), key(1)),
    ] {
        let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&expression).unwrap();
        for plan in [
            descriptor
                .clone()
                .plan(&Assets::fixed(Some(hash(1))))
                .unwrap(),
            descriptor.plan_mall(&Assets::fixed(Some(hash(1)))).unwrap(),
        ] {
            assert_eq!(plan.tx_template, Some(hash(1)), "{}", expression);
            let changed = Complete { template: Some(hash(2)), signatures_requested: Cell::new(0) };
            assert!(plan.satisfy(&changed).is_err());
            assert_eq!(changed.signatures_requested.get(), 0);
        }
    }
    let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&format!(
        "tr({},and_v(txtmpl({}),pk({})))",
        key(2),
        hash(1),
        key(1)
    ))
    .unwrap();
    let key_path = Assets { key_path: true, ..Assets::fixed(Some(hash(1))) };
    assert_eq!(descriptor.plan(&key_path).unwrap().tx_template, None);
    let script = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!(
        "and_v(txtmpl({}),pk({}))",
        hash(1),
        key(1)
    ))
    .unwrap()
    .build_template(&Assets::fixed(Some(hash(1))));
    let mut completion = Complete { template: Some(hash(2)), signatures_requested: Cell::new(0) };
    assert!(script.try_completing(&completion).is_none());
    assert_eq!(completion.signatures_requested.get(), 0);
    completion.template = Some(hash(1));
    assert_eq!(script.try_completing(&completion).unwrap().tx_template, Some(hash(1)));
    assert_eq!(completion.signatures_requested.get(), 1);
}
