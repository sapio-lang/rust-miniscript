extern crate sapio_miniscript as miniscript;

use miniscript::bitcoin::{hashes::hex::FromHex, Script};
use miniscript::ord::{envelope::Envelope, Inscription};

fn discover(hex: &str) -> Vec<Envelope<Inscription>> {
    let script = Script::from(Vec::<u8>::from_hex(hex).unwrap());
    Envelope::from_tapscript(&script, 7)
        .unwrap()
        .into_iter()
        .map(Into::into)
        .collect()
}

#[test]
fn literal_fields_distinguish_duplicates_dangling_tags_and_empty_values() {
    // These bytes are independent of the inscription encoder. In particular,
    // an empty value is not a body delimiter at an odd payload position.
    let cases = [
        (
            "0063036f72640101016100016268",
            Inscription::new(Some(b"a".to_vec()), Some(b"b".to_vec())),
        ),
        (
            "0063036f7264010101610101016268",
            Inscription {
                content_type: Some(b"a".to_vec()),
                duplicate_field: true,
                ..Inscription::default()
            },
        ),
        (
            "0063036f7264010168",
            Inscription {
                incomplete_field: true,
                ..Inscription::default()
            },
        ),
        ("0063036f726401010068", Inscription::new(Some(vec![]), None)),
        ("0063036f72640068", Inscription::new(None, Some(vec![]))),
        ("0063036f726468", Inscription::default()),
    ];
    for (script, expected) in &cases {
        let parsed = discover(script);
        assert_eq!(parsed.len(), 1, "{}", script);
        assert_eq!(parsed[0].payload, *expected, "{}", script);
        assert_eq!((parsed[0].input, parsed[0].offset), (7, 0));
        assert!(!parsed[0].pushnum, "{}", script);
        assert!(!parsed[0].stutter, "{}", script);
    }
}

#[test]
fn pushnum_diagnostics_preserve_script_number_bytes() {
    let cases = [
        ("0063036f7264004f68", vec![0x81]),
        ("0063036f7264005168", vec![1]),
        ("0063036f7264006068", vec![16]),
    ];
    for (script, body) in &cases {
        let parsed = discover(script);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].payload,
            Inscription::new(None, Some(body.clone()))
        );
        assert!(parsed[0].pushnum, "{}", script);
        assert!(!parsed[0].stutter);
    }

    let tagged = discover("0063036f726451016168");
    assert_eq!(tagged.len(), 1);
    assert_eq!(
        tagged[0].payload,
        Inscription::new(Some(b"a".to_vec()), None)
    );
    assert!(tagged[0].pushnum);
}

#[test]
fn stutter_requires_an_adjacent_failed_envelope_prefix() {
    let cases = [
        ("0063036f726400016168", false),
        ("000063036f726400016168", true),
        ("00750063036f726400016168", false),
    ];
    for (script, stutter) in &cases {
        let parsed = discover(script);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].payload,
            Inscription::new(None, Some(b"a".to_vec()))
        );
        assert_eq!(parsed[0].stutter, *stutter, "{}", script);
        assert!(!parsed[0].pushnum);
    }
}

#[test]
fn discovery_requires_the_protocol_prefix_and_a_complete_push_only_payload() {
    for script in &[
        "5163036f726400016168", // OP_1 instead of OP_0
        "00630361626300016168", // another protocol identifier
        "0063036f7264000161",   // missing OP_ENDIF
        "0063036f7264007568",   // OP_DROP is not a payload push
    ] {
        assert!(discover(script).is_empty(), "{}", script);
    }

    // Discovery accepts the protocol identifier in a nonminimal push. This
    // differs from Miniscript's deliberately strict byte-preserving parser.
    let parsed = discover("00634c036f726400016168");
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].payload,
        Inscription::new(None, Some(b"a".to_vec()))
    );
    assert!(!parsed[0].pushnum);
    assert!(!parsed[0].stutter);
}
