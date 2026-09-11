use miniscript::bitcoin::blockdata::script::Builder;
use miniscript::bitcoin::{OutPoint, ScriptBuf as Script, Transaction, TxIn, Witness};
use miniscript::ord::envelope::Envelope;
use miniscript::ord::Inscription;

fn transaction(witnesses: Vec<Vec<Vec<u8>>>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: witnesses
            .into_iter()
            .map(|witness| TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::from_slice(&witness),
            })
            .collect(),
        output: vec![],
    }
}

fn inscription(body: &[u8]) -> Inscription {
    Inscription::new(Some(b"text/plain".to_vec()), Some(body.to_vec()))
}

fn reveal(inscription: &Inscription) -> Vec<u8> {
    inscription
        .append_reveal_script_to_builder(Builder::new())
        .into_script()
        .into_bytes()
}

#[test]
fn transaction_parser_ignores_empty_and_key_path_witnesses() {
    let script = reveal(&inscription(b"not a script-path spend"));
    let tx = transaction(vec![vec![], vec![script.clone()], vec![script, vec![0x50]]]);
    assert!(Envelope::<Inscription>::from_transaction(&tx).is_empty());
}

#[test]
fn transaction_parser_selects_tapscript_with_and_without_annex() {
    let expected = inscription(b"reveal");
    for argument_count in 0..=2 {
        for annex in [false, true] {
            let mut witness = vec![vec![0x01; 64]; argument_count];
            witness.push(reveal(&expected));
            witness.push(vec![0xc0; 33]);
            if annex {
                witness.push(vec![0x50, 0x01]);
            }
            let tx = transaction(vec![witness]);
            let parsed = Envelope::<Inscription>::from_transaction(&tx);
            assert_eq!(parsed.len(), 1, "args={}, annex={}", argument_count, annex);
            assert_eq!(parsed[0].payload, expected);
            assert_eq!((parsed[0].input, parsed[0].offset), (0, 0));
        }
    }
}

#[test]
fn transaction_parser_preserves_input_and_envelope_order() {
    let first = inscription(b"first");
    let second = inscription(b"second");
    let mut script = reveal(&first);
    script.extend(reveal(&second));
    let tx = transaction(vec![vec![], vec![script, vec![0xc0; 33]]]);
    let parsed = Envelope::<Inscription>::from_transaction(&tx);
    assert_eq!(parsed.len(), 2);
    assert_eq!((parsed[0].input, parsed[0].offset), (1, 0));
    assert_eq!((parsed[1].input, parsed[1].offset), (1, 1));
    assert_eq!(parsed[0].payload, first);
    assert_eq!(parsed[1].payload, second);
}

#[test]
fn empty_metadata_keeps_a_field() {
    let mut expected = inscription(b"body");
    expected.metadata = Some(vec![]);
    let raw = Envelope::from_tapscript(&Script::from(reveal(&expected)), 0).unwrap();
    let parsed: Envelope<Inscription> = raw[0].clone().into();
    assert_eq!(parsed.payload.metadata, Some(vec![]));
}

#[test]
fn out_of_range_input_index_returns_an_error() {
    if let Some(index) = (u32::MAX as usize).checked_add(1) {
        let script = Script::from(reveal(&inscription(b"body")));
        assert!(Envelope::from_tapscript(&script, index).is_err());
    }
}

#[test]
fn unchunked_fields_obey_script_element_limit() {
    for field in 0..6 {
        for size in [520, 521] {
            let mut value = Inscription::default();
            let bytes = Some(vec![b'a'; size]);
            match field {
                0 => value.content_type = bytes,
                1 => value.content_encoding = bytes,
                2 => value.metaprotocol = bytes,
                3 => value.parent = bytes,
                4 => value.delegate = bytes,
                5 => value.pointer = bytes,
                _ => unreachable!(),
            }
            assert_eq!(value.validate().is_ok(), size == 520, "field={}, size={}", field, size);
        }
    }
}

#[test]
fn large_body_and_metadata_roundtrip_as_bounded_pushes() {
    use miniscript::bitcoin::blockdata::script::Instruction;

    let mut value = inscription(&vec![42; 1041]);
    value.metadata = Some(vec![43; 1041]);
    value.validate().unwrap();
    let script = Script::from(reveal(&value));
    for instruction in script.instructions() {
        if let Instruction::PushBytes(bytes) = instruction.unwrap() {
            assert!(bytes.len() <= 520);
        }
    }
    let raw = Envelope::from_tapscript(&script, 0).unwrap();
    let parsed: Envelope<Inscription> = raw[0].clone().into();
    assert_eq!(parsed.payload.body, value.body);
    assert_eq!(parsed.payload.metadata, value.metadata);
    assert_eq!(reveal(&parsed.payload), script.into_bytes());
}
