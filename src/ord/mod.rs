// PUBLIC DOMAIN CC0 -- THIS MODULE (AND ITS FILES) IS COPIED FROM ORD WHICH IS
// UNDER CC0

//! Utils for working with ordinals, copied from Ord codebase
use bitcoin::blockdata::constants::MAX_SCRIPT_ELEMENT_SIZE;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{self, Builder};
use bitcoin::hex::DisplayHex;
use bitcoin::{Script, ScriptBuf};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use self::tag::Tag;
use crate::prelude::*;

pub(crate) fn push_bytes(bytes: &[u8]) -> &script::PushBytes {
    bytes.try_into().expect("script push exceeds u32 size")
}

#[allow(missing_docs)]
pub mod envelope;
/// Inscription Type (CC0 ord repo copy)
#[allow(missing_docs)]
pub mod tag;
/// Inscription Type (CC0 ord repo copy)
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Eq, Default, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
impl core::fmt::Display for Inscription {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            self.append_reveal_script_to_builder(Builder::new())
                .into_script()
                .as_bytes()
                .as_hex()
        )
    }
}
pub(crate) const PROTOCOL_ID: &[u8] = b"ord".as_slice();
pub(crate) const BODY_TAG: [u8; 0] = [];
impl Inscription {
    /// Check the consensus push-size bound for fields that cannot be chunked.
    /// Body and metadata are split into script elements by the encoder.
    pub fn validate(&self) -> Result<(), crate::Error> {
        for (name, field) in [
            ("content type", &self.content_type),
            ("content encoding", &self.content_encoding),
            ("metaprotocol", &self.metaprotocol),
            ("parent", &self.parent),
            ("delegate", &self.delegate),
            ("pointer", &self.pointer),
        ]
        .iter()
        {
            if field
                .as_ref()
                .map_or(false, |value| value.len() > MAX_SCRIPT_ELEMENT_SIZE)
            {
                return Err(crate::Error::InscriptionError(format!(
                    "{} exceeds the {}-byte script element limit",
                    name, MAX_SCRIPT_ELEMENT_SIZE
                )));
            }
        }
        Ok(())
    }

    #[allow(missing_docs)]
    pub fn new(content_type: Option<Vec<u8>>, body: Option<Vec<u8>>) -> Self {
        Self { content_type, body, ..Default::default() }
    }
    #[allow(missing_docs)]
    pub fn append_reveal_script_to_builder(&self, mut builder: script::Builder) -> script::Builder {
        builder = builder
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(push_bytes(PROTOCOL_ID));

        Tag::ContentType.encode(&mut builder, &self.content_type);
        Tag::ContentEncoding.encode(&mut builder, &self.content_encoding);
        Tag::Metaprotocol.encode(&mut builder, &self.metaprotocol);
        Tag::Parent.encode(&mut builder, &self.parent);
        Tag::Delegate.encode(&mut builder, &self.delegate);
        Tag::Pointer.encode(&mut builder, &self.pointer);
        Tag::Metadata.encode(&mut builder, &self.metadata);

        if let Some(body) = &self.body {
            builder = builder.push_slice(BODY_TAG);
            for chunk in body.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
                builder = builder.push_slice(push_bytes(chunk));
            }
        }

        builder.push_opcode(opcodes::all::OP_ENDIF)
    }
    // TODO: make efficient
    /// Returns the exact encoded envelope size in bytes.
    pub fn size_guess(&self) -> usize {
        let b = script::Builder::new();
        self.append_reveal_script_to_builder(b).len()
    }

    /// Counts the encoded envelope instructions, including pushes.
    pub fn instruction_count(&self) -> usize {
        let b = script::Builder::new();
        let script: ScriptBuf = self.append_reveal_script_to_builder(b).into_script();
        script.instructions().count()
    }
}

// A Miniscript is a commitment to exact script bytes. The discovery scanner is
// deliberately permissive, but its interpreted fields cannot preserve arbitrary
// encodings or unknown fields. Accept only complete, reconstructable envelopes.
pub(crate) fn parse_inscriptions(script: &Script) -> Result<Vec<Inscription>, crate::Error> {
    let raw = envelope::Envelope::from_tapscript(script, 0)
        .map_err(|error| crate::Error::InscriptionError(error.to_string()))?;
    if raw.is_empty() {
        return Err(crate::Error::InscriptionError("expected an inscription envelope".into()));
    }
    let inscriptions: Vec<_> = raw
        .into_iter()
        .map(|raw| {
            let parsed: envelope::Envelope<Inscription> = raw.into();
            parsed.payload
        })
        .collect();
    let mut builder = Builder::new();
    for inscription in &inscriptions {
        inscription.validate()?;
        builder = inscription.append_reveal_script_to_builder(builder);
    }
    if builder.into_script() != *script {
        return Err(crate::Error::InscriptionError(
            "envelope cannot be represented without changing its script bytes".into(),
        ));
    }
    Ok(inscriptions)
}
