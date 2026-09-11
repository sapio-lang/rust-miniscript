use miniscript::bitcoin::{ScriptBuf as Script, XOnlyPublicKey};
use miniscript::{Miniscript, Tap};

const KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const EMPTY: &str = "0063036f726468";
const CONTENT: &str = "0063036f726401010a746578742f706c61696e00016168";
type TapScript = Miniscript<XOnlyPublicKey, Tap>;

fn check_roundtrip(expression: &str) {
    let parsed = TapScript::from_str_insane(expression).unwrap();
    let script = parsed.encode();
    let decoded = TapScript::decode_with_ext(&script, &miniscript::ExtParams::insane()).unwrap();
    assert_eq!(decoded.encode(), script);
    assert_eq!(TapScript::from_str_insane(&parsed.to_string()).unwrap(), parsed);
    assert!(!format!("{:?}", parsed).is_empty());
}

#[test]
fn inscription_pre_and_post_roundtrip() {
    for envelope in &[EMPTY, CONTENT] {
        for wrapper in &["inscribe_pre", "inscribe_post"] {
            check_roundtrip(&format!("{}({},pk({}))", wrapper, envelope, KEY));
        }
    }
}

#[test]
fn inscriptions_roundtrip_inside_combinators() {
    for expression in &[
        format!(
            "and_v(v:inscribe_pre({},pk({})),inscribe_post({},pk({})))",
            CONTENT, KEY, EMPTY, KEY
        ),
        format!(
            "or_i(inscribe_pre({},pk({})),inscribe_post({},pk({})))",
            CONTENT, KEY, EMPTY, KEY
        ),
        format!("inscribe_pre({},inscribe_post({},pk({})))", CONTENT, EMPTY, KEY),
        format!("inscribe_pre({}{},pk({}))", CONTENT, EMPTY, KEY),
        format!("inscribe_post({}{},pk({}))", CONTENT, EMPTY, KEY),
        format!(
            "and_b(inscribe_pre({},pk({})),inscribe_pre({},s:pk({})))",
            CONTENT, KEY, EMPTY, KEY
        ),
    ] {
        check_roundtrip(expression);
    }
}

#[test]
fn inscription_text_rejects_lossy_payloads() {
    for envelope in &[
        "",
        "51",
        "0063036f7264",
        "510063036f726468",
        "0063036f72646851",
        "0063036f726401ff017868",         // Unknown field.
        "0063036f7264010101610101016268", // Duplicate content type.
        "0063036f7264010168",             // Incomplete field.
        "0063036f726451016168",           // Pushnum tag changes its encoding.
    ] {
        let expression = format!("inscribe_pre({},pk({}))", envelope, KEY);
        assert!(TapScript::from_str_insane(&expression).is_err(), "{}", expression);
    }
}

#[test]
fn inscription_binary_rejects_unterminated_or_lossy_envelopes() {
    for envelope in &[
        "0063036f7264",
        "0063036f726401010161",
        "0063036f726401ff017868",
        "0063036f726451016168",
        "00634c036f726468",
        "0063036f72644c0101016168",
    ] {
        let script = Script::from_hex(&format!("20{}ac{}", KEY, envelope)).unwrap();
        assert!(
            TapScript::decode_with_ext(&script, &miniscript::ExtParams::insane()).is_err(),
            "{}",
            envelope
        );
    }
}

#[test]
fn inscription_parsing_preserves_minimal_push_rules_outside_envelopes() {
    check_roundtrip(&format!("inscribe_pre({},older(17))", EMPTY));
    for executable in &[
        "0101b2",     // CSV with a nonminimal one-byte number push.
        "4c0101b2",   // CSV with an unnecessary PUSHDATA1.
        "4d010011b2", // CSV with an unnecessary PUSHDATA2.
    ] {
        let script = Script::from_hex(&format!("{}{}", EMPTY, executable)).unwrap();
        assert!(TapScript::decode_with_ext(&script, &miniscript::ExtParams::insane()).is_err());
    }
}

#[test]
fn inscription_lexer_requires_closed_envelopes() {
    for script in &["0063036f7264", "0063036f7264000161"] {
        assert!(matches!(
            miniscript::miniscript::lex::lex(&Script::from_hex(script).unwrap()),
            Err(miniscript::miniscript::lex::Error::Inscription(_))
        ));
    }
}

#[test]
fn inscriptions_roundtrip_around_w_and_k_fragments() {
    for wrapper in &["a", "s"] {
        for inscription in &["inscribe_pre", "inscribe_post"] {
            check_roundtrip(&format!(
                "and_b(pk({}),{}({},{}:pk({})))",
                KEY, inscription, EMPTY, wrapper, KEY
            ));
        }
    }
    for inscription in &["inscribe_pre", "inscribe_post"] {
        check_roundtrip(&format!("c:{}({},pk_k({}))", inscription, EMPTY, KEY));
    }
}
