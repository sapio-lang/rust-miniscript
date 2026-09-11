//! Bounded, deterministic checks of inscription commitment preservation.
#[cfg(feature = "serde")]
extern crate serde_json;

use std::str::FromStr;
use std::sync::Arc;

use miniscript::bitcoin::blockdata::script::Builder;
use miniscript::bitcoin::hex::DisplayHex;
use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::taproot::TaprootBuilder;
use miniscript::bitcoin::{ScriptBuf as Script, XOnlyPublicKey};
use miniscript::descriptor::TapTree;
use miniscript::ord::envelope::Envelope;
use miniscript::ord::Inscription;
use miniscript::{Descriptor, Miniscript, Tap};

const KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const INTERNAL: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const EMPTY: &[u8] = b"\x00\x63\x03ord\x68";
// Authoring order, with the body separator handled separately.
const TAGS: [u8; 7] = [1, 9, 7, 3, 11, 2, 5];
type Ms = Miniscript<XOnlyPublicKey, Tap>;

fn fields(value: &Inscription) -> [Option<&[u8]>; 8] {
    [
        value.content_type.as_deref(),
        value.content_encoding.as_deref(),
        value.metaprotocol.as_deref(),
        value.parent.as_deref(),
        value.delegate.as_deref(),
        value.pointer.as_deref(),
        value.metadata.as_deref(),
        value.body.as_deref(),
    ]
}

fn set_field(value: &mut Inscription, field: usize, bytes: Option<Vec<u8>>) {
    match field {
        0 => value.content_type = bytes,
        1 => value.content_encoding = bytes,
        2 => value.metaprotocol = bytes,
        3 => value.parent = bytes,
        4 => value.delegate = bytes,
        5 => value.pointer = bytes,
        6 => value.metadata = bytes,
        7 => value.body = bytes,
        _ => unreachable!(),
    }
}

fn reveal(value: &Inscription) -> Script {
    value
        .append_reveal_script_to_builder(Builder::new())
        .into_script()
}

// Literal push headers for the tested consensus boundaries. In particular,
// byte values 1..16 and 0x81 remain data pushes inside an unexecuted envelope.
fn push_fixture(bytes: &[u8], script: &mut Vec<u8>) {
    let header: &[u8] = match bytes.len() {
        0 => &[0],
        1 => &[1],
        2 => &[2],
        75 => &[75],
        76 => &[0x4c, 76],
        255 => &[0x4c, 255],
        256 => &[0x4d, 0, 1],
        519 => &[0x4d, 7, 2],
        520 => &[0x4d, 8, 2],
        _ => panic!("missing boundary fixture for {} bytes", bytes.len()),
    };
    script.extend_from_slice(header);
    script.extend_from_slice(bytes);
}

fn field_fixture(field: usize, bytes: &[u8]) -> Vec<u8> {
    let mut script = b"\x00\x63\x03ord".to_vec();
    if field == 7 {
        script.push(0);
        for chunk in bytes.chunks(520) {
            push_fixture(chunk, &mut script);
        }
    } else {
        let chunks: Vec<_> = if field == 6 && !bytes.is_empty() {
            bytes.chunks(520).collect()
        } else {
            vec![bytes]
        };
        for chunk in chunks {
            script.extend_from_slice(&[1, TAGS[field]]);
            push_fixture(chunk, &mut script);
        }
    }
    script.push(0x68);
    script
}

fn assert_descriptor_commitment(ms: &Ms, script: &Script) {
    let internal = XOnlyPublicKey::from_str(INTERNAL).unwrap();
    let descriptor = Descriptor::new_tr(internal, Some(TapTree::leaf(ms.clone()))).unwrap();
    // Compare against a tree built directly from the expected wire script,
    // independently of Miniscript's descriptor parser and encoder.
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&Secp256k1::new(), internal)
        .unwrap();
    let expected = Script::new_p2tr_tweaked(spend.output_key());
    assert_eq!(descriptor.script_pubkey(), expected);
    let restored = Descriptor::<XOnlyPublicKey>::from_str(&descriptor.to_string()).unwrap();
    assert_eq!(restored.script_pubkey(), expected);
    #[cfg(feature = "serde")]
    {
        let restored: Descriptor<XOnlyPublicKey> =
            serde_json::from_str(&serde_json::to_string(&descriptor).unwrap()).unwrap();
        assert_eq!(restored.script_pubkey(), expected);
        let restored: Ms = serde_json::from_str(&serde_json::to_string(ms).unwrap()).unwrap();
        assert_eq!(restored.encode(), *script);
    }
}

fn assert_wrapped_commitments(envelope: &[u8]) {
    let key_script = Script::from_hex(&format!("20{}ac", KEY)).unwrap();
    for post in [false, true] {
        let expression = format!(
            "inscribe_{}({},pk({}))",
            if post { "post" } else { "pre" },
            envelope.as_hex().to_string(),
            KEY
        );
        let ms = Ms::from_str(&expression).unwrap();
        let mut expected = if post {
            key_script.to_bytes()
        } else {
            envelope.to_vec()
        };
        expected.extend_from_slice(if post {
            envelope
        } else {
            key_script.as_bytes()
        });
        let expected = Script::from(expected);
        assert_eq!(ms.encode(), expected);
        assert_eq!(Ms::decode(&expected).unwrap().encode(), expected);
        assert_eq!(Ms::from_str(&ms.to_string()).unwrap().encode(), expected);
        assert_descriptor_commitment(&ms, &expected);
    }
}

#[test]
fn all_fields_preserve_absence_empty_values_and_push_boundaries() {
    assert_eq!(reveal(&Inscription::default()).as_bytes(), EMPTY);
    assert_wrapped_commitments(EMPTY);
    for field in 0..8 {
        let mut lengths = vec![0, 1, 2, 75, 76, 255, 256, 519, 520];
        if field >= 6 {
            lengths.extend_from_slice(&[521, 1040, 1041]);
        }
        for length in lengths {
            let bytes: Vec<_> = (0..length)
                .map(|index| (index as u8).wrapping_mul(131).wrapping_add(field as u8))
                .collect();
            let mut value = Inscription::default();
            set_field(&mut value, field, Some(bytes.clone()));
            let expected = field_fixture(field, &bytes);
            assert_eq!(reveal(&value).as_bytes(), expected, "field={}, length={}", field, length);
            let raw = Envelope::from_tapscript(&Script::from(expected.clone()), 3).unwrap();
            assert_eq!(raw.len(), 1);
            let parsed: Envelope<Inscription> = raw[0].clone().into();
            assert_eq!(fields(&parsed.payload), fields(&value));
            assert_eq!(parsed.payload.duplicate_field, field == 6 && length > 520);
            assert_wrapped_commitments(&expected);
            #[cfg(feature = "serde")]
            {
                let restored: Inscription =
                    serde_json::from_str(&serde_json::to_string(&value).unwrap()).unwrap();
                assert_eq!(restored, value);
            }
        }
    }
}

#[test]
fn single_byte_data_is_never_rewritten_as_a_numeric_opcode() {
    for byte in [0, 1, 2, 16, 17, 0x50, 0x63, 0x68, 0x81, 0xff] {
        for field in 0..8 {
            let mut value = Inscription::default();
            set_field(&mut value, field, Some(vec![byte]));
            let expected = field_fixture(field, &[byte]);
            assert_eq!(reveal(&value).as_bytes(), expected);
            assert_wrapped_commitments(&expected);
        }
    }
}

#[test]
fn generated_field_combinations_preserve_payloads_and_commitments() {
    // Fixed arithmetic seeds cover absent, empty and nonempty values in every
    // field, including non-UTF8 data and opcode bytes inside pushed content.
    for seed in 0usize..64 {
        let mut value = Inscription::default();
        for field in 0..8 {
            let selector = (seed.rotate_left(field as u32) ^ (field * 13)) % 5;
            let bytes = match selector {
                0 => None,
                1 => Some(vec![]),
                2 => Some(vec![seed as u8]),
                _ => Some(
                    (0..(selector * 79))
                        .map(|i| (i * 37 + seed) as u8)
                        .collect(),
                ),
            };
            set_field(&mut value, field, bytes);
        }
        let script = reveal(&value);
        let raw = Envelope::from_tapscript(&script, 0).unwrap();
        let parsed: Envelope<Inscription> = raw[0].clone().into();
        assert_eq!(fields(&parsed.payload), fields(&value));
        assert_wrapped_commitments(script.as_bytes());
    }
}

#[test]
fn truncation_at_every_byte_rejects_incomplete_envelopes() {
    let mut fixtures = vec![EMPTY.to_vec()];
    fixtures.push(field_fixture(0, &[0x5a; 76]));
    fixtures.push(field_fixture(6, &vec![0x5a; 521]));
    fixtures.push(field_fixture(7, &vec![0x5a; 1041]));
    for envelope in fixtures {
        for end in 0..envelope.len() {
            let bytes = &envelope[..end];
            let text = format!("inscribe_post({},pk({}))", bytes.as_hex().to_string(), KEY);
            assert!(Ms::from_str(&text).is_err(), "prefix {} of {}", end, envelope.len());
            let script =
                Script::from_hex(&format!("20{}ac{}", KEY, bytes.as_hex().to_string())).unwrap();
            if end == 0 {
                // Removing the entire suffix leaves the original key script.
                assert_eq!(Ms::decode(&script).unwrap().encode(), script);
            } else {
                assert!(
                    Ms::decode_with_ext(&script, &miniscript::ExtParams::insane()).is_err(),
                    "prefix {} of {}",
                    end,
                    envelope.len()
                );
            }
        }
    }
}

#[test]
fn unknown_tags_are_discoverable_but_cannot_change_a_miniscript_commitment() {
    for tag in 0u8..=255 {
        if TAGS.contains(&tag) {
            continue;
        }
        let mut envelope = b"\x00\x63\x03ord".to_vec();
        envelope.extend_from_slice(&[1, tag, 1, 0x42, 0x68]);
        let raw = Envelope::from_tapscript(&Script::from(envelope.clone()), 0).unwrap();
        assert_eq!(raw.len(), 1);
        let parsed: Envelope<Inscription> = raw[0].clone().into();
        assert_eq!(parsed.payload.unrecognized_even_field, tag % 2 == 0);
        let text = format!("inscribe_pre({},pk({}))", envelope.as_hex().to_string(), KEY);
        assert!(Ms::from_str(&text).is_err(), "tag={}", tag);
        let script =
            Script::from_hex(&format!("{}20{}ac", envelope.as_hex().to_string(), KEY)).unwrap();
        assert!(
            Ms::decode_with_ext(&script, &miniscript::ExtParams::insane()).is_err(),
            "tag={}",
            tag
        );
    }
}

fn next_permutation(values: &mut [usize]) -> bool {
    let Some(index) = (0..values.len() - 1)
        .rev()
        .find(|&i| values[i] < values[i + 1])
    else {
        return false;
    };
    let swap = (index + 1..values.len())
        .rev()
        .find(|&i| values[i] > values[index])
        .unwrap();
    values.swap(index, swap);
    values[index + 1..].reverse();
    true
}

#[test]
fn all_header_field_orders_preserve_or_reject_the_original_bytes() {
    let mut order = [0, 1, 2, 3, 4, 5, 6];
    let mut count = 0;
    loop {
        let mut envelope = b"\x00\x63\x03ord".to_vec();
        for &field in &order {
            envelope.extend_from_slice(&[1, TAGS[field], 1, 0x42]);
        }
        envelope.push(0x68);
        let text = format!("inscribe_pre({},pk({}))", envelope.as_hex().to_string(), KEY);
        let result = Ms::from_str(&text);
        assert_eq!(result.is_ok(), order == [0, 1, 2, 3, 4, 5, 6], "order={:?}", order);
        count += 1;
        if !next_permutation(&mut order) {
            break;
        }
    }
    assert_eq!(count, 5040);
}

#[test]
fn every_single_bit_mutation_is_rejected_or_preserves_exact_script_bytes() {
    let mut envelope = field_fixture(0, &[0x42, 0x43]);
    envelope.pop();
    envelope.extend_from_slice(b"\x00\x02\x63\x68\x68");
    for index in 0..envelope.len() {
        for bit in 0..8 {
            let mut mutated = envelope.clone();
            mutated[index] ^= 1 << bit;
            for post in [false, true] {
                let script = if post {
                    format!("20{}ac{}", KEY, mutated.as_hex().to_string())
                } else {
                    format!("{}20{}ac", mutated.as_hex().to_string(), KEY)
                };
                let script = Script::from_hex(&script).unwrap();
                if let Ok(parsed) = Ms::decode_with_ext(&script, &miniscript::ExtParams::insane()) {
                    assert_eq!(
                        parsed.encode(),
                        script,
                        "index={}, bit={}, post={}",
                        index,
                        bit,
                        post
                    );
                }
            }
        }
    }
}

#[test]
fn generated_nested_combinators_preserve_all_script_commitments() {
    let first = field_fixture(7, &[0x63]);
    let second = field_fixture(7, &[0x68]);
    let children = [
        format!("pk({})", KEY),
        format!("or_i(pk({}),pk({}))", KEY, INTERNAL),
        format!("and_v(v:pk({}),pk({}))", KEY, INTERNAL),
        format!("and_b(pk({}),a:pk({}))", KEY, INTERNAL),
        format!("thresh(1,pk({}),a:pk({}))", KEY, INTERNAL),
    ];
    for child in &children {
        for initial_post in [false, true] {
            let mut text = child.clone();
            let mut expected = Ms::from_str(&text).unwrap().encode().into_bytes();
            for depth in 0..4 {
                let envelope = if depth % 2 == 0 { &first } else { &second };
                let post = initial_post ^ (depth % 2 == 1);
                text = format!(
                    "inscribe_{}({},{})",
                    if post { "post" } else { "pre" },
                    envelope.as_hex().to_string(),
                    text
                );
                if post {
                    expected.extend_from_slice(envelope);
                } else {
                    let mut prefixed = envelope.clone();
                    prefixed.extend_from_slice(&expected);
                    expected = prefixed;
                }
                let ms = Ms::from_str(&text).unwrap();
                let script = Script::from(expected.clone());
                assert_eq!(ms.encode(), script);
                assert_eq!(Ms::decode(&script).unwrap().encode(), script);
                assert_descriptor_commitment(&ms, &script);
            }
        }
    }
}

#[test]
fn nested_taproot_descriptor_preserves_leaf_bytes_and_output_key() {
    let texts = [
        format!("inscribe_pre({},pk({}))", field_fixture(7, &[0x00]).as_hex().to_string(), KEY),
        format!(
            "inscribe_post({},pk({}))",
            field_fixture(7, &[0x81]).as_hex().to_string(),
            INTERNAL
        ),
        format!(
            "inscribe_pre({},or_i(pk({}),pk({})))",
            field_fixture(6, &[0x63, 0x68]).as_hex().to_string(),
            KEY,
            INTERNAL
        ),
    ];
    let leaves: Vec<_> = texts
        .iter()
        .map(|text| Arc::new(Ms::from_str(text).unwrap()))
        .collect();
    let tree = TapTree::combine(
        TapTree::leaf(leaves[0].clone()),
        TapTree::combine(TapTree::leaf(leaves[1].clone()), TapTree::leaf(leaves[2].clone()))
            .unwrap(),
    )
    .unwrap();
    let internal = XOnlyPublicKey::from_str(INTERNAL).unwrap();
    let descriptor = Descriptor::new_tr(internal, Some(tree)).unwrap();
    let mut builder = TaprootBuilder::new();
    for (depth, leaf) in [1, 2, 2].iter().zip(&leaves) {
        builder = builder.add_leaf(*depth, leaf.encode()).unwrap();
    }
    let spend = builder.finalize(&Secp256k1::new(), internal).unwrap();
    let expected = Script::new_p2tr_tweaked(spend.output_key());
    assert_eq!(descriptor.script_pubkey(), expected);
    let restored = Descriptor::<XOnlyPublicKey>::from_str(&descriptor.to_string()).unwrap();
    assert_eq!(restored.script_pubkey(), expected);
    if let Descriptor::Tr(restored) = &restored {
        let scripts: Vec<_> = restored
            .leaves()
            .map(|leaf| (leaf.depth(), leaf.miniscript().encode()))
            .collect();
        assert_eq!(
            scripts,
            vec![
                (1, leaves[0].encode()),
                (2, leaves[1].encode()),
                (2, leaves[2].encode())
            ]
        );
    } else {
        panic!("changed descriptor type");
    }
    #[cfg(feature = "serde")]
    {
        let restored: Descriptor<XOnlyPublicKey> =
            serde_json::from_str(&serde_json::to_string(&descriptor).unwrap()).unwrap();
        assert_eq!(restored.script_pubkey(), expected);
    }
}

#[test]
fn noncanonical_pushes_chunks_and_oversized_fields_are_rejected() {
    let mut envelopes = Vec::new();
    for field in 0..6 {
        let mut value = Inscription::default();
        set_field(&mut value, field, Some(vec![0x42; 521]));
        envelopes.push(reveal(&value));
    }
    // These envelopes are discoverable, but reconstructing their fields
    // would change a push opcode, merge chunks or remove an empty push.
    for hex in &[
        "0063036f72644c0101014268",       // PUSHDATA1 tag.
        "0063036f72644d010001014268",     // PUSHDATA2 tag.
        "0063036f72644e0100000001014268", // PUSHDATA4 tag.
        "0063036f726401014c014268",       // PUSHDATA1 field value.
        "0063036f726401014d01004268",     // PUSHDATA2 field value.
        "0063036f726401014e010000004268", // PUSHDATA4 field value.
        "0063036f72644c00014268",         // Nonminimal body separator.
        "0063036f7264000142014368",       // Two sub-limit body chunks.
        "0063036f7264010501420105014368", // Two sub-limit metadata chunks.
        "0063036f7264000068",             // Redundant empty body push.
        "0063036f7264020100014268",       // A two-byte tag must not alias tag1.
        "0063036f7264010101420168",       // A truncated trailing field.
    ] {
        envelopes.push(Script::from_hex(hex).unwrap());
    }
    for envelope in envelopes {
        let text =
            format!("inscribe_pre({},pk({}))", envelope.as_bytes().as_hex().to_string(), KEY);
        assert!(Ms::from_str(&text).is_err(), "{}", text);
        let descriptor = format!("tr({},{})", INTERNAL, text);
        assert!(Descriptor::<XOnlyPublicKey>::from_str(&descriptor).is_err());
        let script =
            Script::from_hex(&format!("{}20{}ac", envelope.as_bytes().as_hex().to_string(), KEY))
                .unwrap();
        assert!(Ms::decode_with_ext(&script, &miniscript::ExtParams::insane()).is_err());
    }
}
