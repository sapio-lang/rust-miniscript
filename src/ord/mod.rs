// PUBLIC DOMAIN CC0 -- THIS MODULE (AND ITS FILES) IS COPIED FROM ORD WHICH IS
// UNDER CC0

///! Utils for working with ordinals, copied from Ord codebase
use bitcoin::{
    blockdata::{
        constants::MAX_SCRIPT_ELEMENT_SIZE,
        opcodes,
        script::{self, Builder},
    },
    hashes::hex::ToHex,
    Script,
};
#[cfg(feature = "schemars")]
use schemars::JsonSchema;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use self::tag::Tag;

#[allow(missing_docs)]
pub mod envelope;
/// Inscription Type (CC0 ord repo copy)
#[allow(missing_docs)]
pub mod tag;
/// Inscription Type (CC0 ord repo copy)
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Eq, Default, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "schemars", derive(JsonSchema))]
pub struct Inscription {
    pub body: Option<Vec<u8>>,
    pub content_encoding: Option<Vec<u8>>,
    pub content_type: Option<Vec<u8>>,
    pub delegate: Option<Vec<u8>>,
    pub duplicate_field: bool,
    pub incomplete_field: bool,
    pub metadata: Option<Vec<u8>>,
    pub metaprotocol: Option<Vec<u8>>,
    pub parent: Option<Vec<u8>>,
    pub pointer: Option<Vec<u8>>,
    pub unrecognized_even_field: bool,
}
impl std::fmt::Display for Inscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.append_reveal_script_to_builder(Builder::new())
                .into_script()
                .to_hex()
        )
    }
}
pub(crate) const PROTOCOL_ID: [u8; 3] = *b"ord";
pub(crate) const BODY_TAG: [u8; 0] = [];
impl Inscription {
    #[allow(missing_docs)]
    pub fn new(content_type: Option<Vec<u8>>, body: Option<Vec<u8>>) -> Self {
        Self {
            content_type,
            body,
            ..Default::default()
        }
    }
    #[allow(missing_docs)]
    pub fn append_reveal_script_to_builder(&self, mut builder: script::Builder) -> script::Builder {
        builder = builder
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(&PROTOCOL_ID);

        Tag::ContentType.encode(&mut builder, &self.content_type);
        Tag::ContentEncoding.encode(&mut builder, &self.content_encoding);
        Tag::Metaprotocol.encode(&mut builder, &self.metaprotocol);
        Tag::Parent.encode(&mut builder, &self.parent);
        Tag::Delegate.encode(&mut builder, &self.delegate);
        Tag::Pointer.encode(&mut builder, &self.pointer);
        Tag::Metadata.encode(&mut builder, &self.metadata);

        if let Some(body) = &self.body {
            builder = builder.push_slice(&BODY_TAG);
            for chunk in body.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
                builder = builder.push_slice(chunk);
            }
        }

        builder.push_opcode(opcodes::all::OP_ENDIF)
    }
    // TODO: make efficient
    pub fn size_guess(&self) -> usize {
        let b = script::Builder::new();
        self.append_reveal_script_to_builder(b).len()
    }

    pub fn instruction_count(&self) -> usize {
        let b = script::Builder::new();
        let script: Script = self.append_reveal_script_to_builder(b).into_script();
        script.instructions().count()
    }
}

#[cfg(test)]
mod test {

    use bitcoin::XOnlyPublicKey;

    use crate::policy::Concrete;

    use super::Inscription;

    #[test]
    #[cfg(feature = "compiler")]
    fn basic_working() {
        use bitcoin::{secp256k1::Secp256k1, util, Script};

        use crate::{
            ord::envelope::{Envelope, ParsedEnvelope},
            Miniscript, Tap,
        };

        let secp = Secp256k1::new();
        let k = util::key::KeyPair::from_seckey_slice(&secp, &[2u8; 32][..]).unwrap();
        let test_inscription = Inscription::new(Some("test".into()), Some("body".into()));
        let script = Concrete::Inscribe(
            Box::new(test_inscription.clone()),
            Box::new(Concrete::Key(k.x_only_public_key().0)),
        );
        println!("{:?}", script);
        let script: Miniscript<XOnlyPublicKey, Tap> = script.compile().unwrap();
        match script.node {
            crate::Terminal::InscribePost(ref insc, _)
            | crate::Terminal::InscribePre(ref insc, _) => {
                assert_eq!(insc[0].content_type, Some("test".into()));
                assert_eq!(insc[0].body, Some("body".into()));
            }
            _ => unreachable!("Wrong Branch"),
        }
        let btc_script: Script = script.encode();
        let envelopes = Envelope::from_tapscript(&btc_script, 0).expect("Should have parsed");
        let parsed: ParsedEnvelope = envelopes[0].clone().into();
        assert_eq!(parsed.payload, test_inscription);
        println!("{:?}", script.to_string());
    }
}
