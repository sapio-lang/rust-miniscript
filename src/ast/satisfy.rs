// Script Descriptor Language
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Satisfaction and Dissatisfaction
//!
//! Traits and implementations to support producing witnesses for scriptpubkeys
//! described by script ASTs.
//!

use std::collections::HashMap;

use bitcoin::util::hash::Hash160;
use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d
use secp256k1;

use super::Error;
use ast::astelem::{AstElem, E, W, F, V, T};

/// Trait describing an AST element which can be satisfied, given maps from the
/// public data to corresponding witness data.
pub trait Satisfiable: AstElem {
    /// Attempt to produce a witness that satisfies the AST element
    fn satisfy(
        &self,
        key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
        hash_map: &HashMap<Sha256dHash, [u8; 32]>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>;

    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    fn required_keys(&self) -> Vec<secp256k1::PublicKey>;
}

/// Trait describing an AST element which can be dissatisfied (without failing the
/// whole script). This only applies to `E` and `W`, since the other AST elements
/// are expected to fail the script on error.
pub trait Dissatisfiable: AstElem {
    /// Attempt to produce a witness that dissatisfies the AST element. Because
    /// pay-to-pubkey-hash fragments require a public key, which is not necessarily
    /// known even if the fragment is, this function requires a map from hashes to
    /// their preimages, and may fail.
    fn dissatisfy(
        &self,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
    ) -> Result<Vec<Vec<u8>>, Error>;
}

impl Satisfiable for E {
    fn satisfy(
        &self,
        key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
        hash_map: &HashMap<Sha256dHash, [u8; 32]>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match *self {
            E::CheckSig(ref pk) => satisfy_checksig(pk, key_map),
            E::CheckSigHash(ref hash) | E::CheckSigHashF(ref hash) => satisfy_checksighash(hash, key_map, pkh_map),
            E::CheckMultiSig(k, ref keys) | E::CheckMultiSigF(k, ref keys) => satisfy_checkmultisig(k, keys, key_map),
            E::HashEqual(ref hash) => satisfy_hashequal(hash, hash_map),
            E::Csv(n) => satisfy_csv(n, age).map(|_| vec![vec![1]]),
            E::Threshold(k, ref sube, ref subw) => satisfy_threshold(k, sube, subw, key_map, pkh_map, hash_map, age),
            E::ParallelAnd(ref left, ref right) => {
                let mut ret = left.satisfy(key_map, pkh_map, hash_map, age)?;
                ret.extend(right.satisfy(key_map, pkh_map, hash_map, age)?);
                Ok(ret)
            }
            E::CascadeAnd(ref left, ref right) => {
                let mut ret = left.satisfy(key_map, pkh_map, hash_map, age)?;
                ret.extend(right.satisfy(key_map, pkh_map, hash_map, age)?);
                Ok(ret)
            }
            E::ParallelOr(ref left, ref right) => satisfy_parallel_or(left, right, key_map, pkh_map, hash_map, age),
            E::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, key_map, pkh_map, hash_map, age),
            E::SwitchOrLeft(ref left, ref right) => satisfy_switch_or(left, right, key_map, pkh_map, hash_map, age),
            E::SwitchOrRight(ref left, ref right) => satisfy_switch_or(right, left, key_map, pkh_map, hash_map, age),
            E::Likely(ref fexpr) => {
                let mut ret = vec![vec![]];
                ret.extend(fexpr.satisfy(key_map, pkh_map, hash_map, age)?);
                Ok(ret)
            }
            E::Unlikely(ref fexpr) => {
                let mut ret = vec![vec![1]];
                ret.extend(fexpr.satisfy(key_map, pkh_map, hash_map, age)?);
                Ok(ret)
            }
        }
    }

    fn required_keys(&self) -> Vec<secp256k1::PublicKey> {
        match *self {
            E::CheckSig(pk) => vec![pk],
            E::CheckSigHash(..) | E::CheckSigHashF(..) | E::HashEqual(..) | E::Csv(..) => vec![],
            E::CheckMultiSig(_, ref keys) | E::CheckMultiSigF(_, ref keys) => keys.clone(),
            E::Threshold(_, ref sube, ref subw) => {
                let mut ret = sube.required_keys();
                for sub in subw {
                    ret.extend(sub.required_keys());
                }
                ret
            }
            E::ParallelAnd(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            E::CascadeAnd(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            E::ParallelOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            E::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            E::SwitchOrLeft(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            E::SwitchOrRight(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            E::Likely(ref fexpr) | E::Unlikely(ref fexpr) => {
                fexpr.required_keys()
            }
        }
    }
}

impl Dissatisfiable for E {
    fn dissatisfy(
        &self,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match *self {
            E::CheckSig(..) => Ok(vec![vec![]]),
            E::CheckSigHash(hash) | E::CheckSigHashF(hash) => {
                if let Some(pk) = pkh_map.get(&hash) {
                    Ok(vec![
                        vec![],
                        pk.serialize()[..].to_owned(),
                    ])
                } else {
                    Err(Error::MissingPubkey(hash))
                }
            }
            E::CheckMultiSig(k, _) | E::CheckMultiSigF(k, _) => {
                Ok(vec![vec![]; k + 1])
            }
            E::HashEqual(..) => Ok(vec![vec![]]),
            E::Csv(..) => Ok(vec![vec![]]),
            E::Threshold(_, ref sube, ref subw) => {
                let mut ret = sube.dissatisfy(pkh_map)?;
                for sub in subw {
                    ret.extend(sub.dissatisfy(pkh_map)?);
                }
                Ok(ret)
            }
            E::ParallelAnd(ref left, ref right) => {
                let mut ret = left.dissatisfy(pkh_map)?;
                ret.extend(right.dissatisfy(pkh_map)?);
                Ok(ret)
            }
            E::CascadeAnd(ref left, _) => left.dissatisfy(pkh_map),
            E::ParallelOr(ref left, ref right) => {
                let mut ret = left.dissatisfy(pkh_map)?;
                ret.extend(right.dissatisfy(pkh_map)?);
                Ok(ret)
            }
            E::Likely(..) => Ok(vec![vec![1]]),
            E::CascadeOr(ref left, ref right) => {
                let mut ret = left.dissatisfy(pkh_map)?;
                ret.extend(right.dissatisfy(pkh_map)?);
                Ok(ret)
            }
            E::SwitchOrLeft(ref left, _) => {
                let mut ret = vec![vec![1]];
                ret.extend(left.dissatisfy(pkh_map)?);
                Ok(ret)
            }
            E::SwitchOrRight(ref left, _) => {
                let mut ret = vec![vec![]];
                ret.extend(left.dissatisfy(pkh_map)?);
                Ok(ret)
            }
            E::Unlikely(..) => Ok(vec![vec![]]),
        }
    }
}

impl Satisfiable for W {
    fn satisfy(
        &self,
        key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
        hash_map: &HashMap<Sha256dHash, [u8; 32]>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match *self {
            W::CheckSig(ref pk) => satisfy_checksig(pk, key_map),
            W::HashEqual(ref hash) => satisfy_hashequal(hash, hash_map),
            W::Csv(n) => satisfy_csv(n, age).map(|_| vec![vec![1]]),
            W::CastE(ref e) => e.satisfy(key_map, pkh_map, hash_map, age)
        }
    }

    fn required_keys(&self) -> Vec<secp256k1::PublicKey> {
        match *self {
            W::CheckSig(ref pk) => vec![*pk],
            W::HashEqual(..) => vec![],
            W::Csv(..) => vec![],
            W::CastE(ref e) => e.required_keys(),
        }
    }
}

impl Dissatisfiable for W {
    fn dissatisfy(
        &self,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match *self {
            W::CheckSig(..) => Ok(vec![]),
            W::HashEqual(..) => Ok(vec![]),
            W::Csv(..) => Ok(vec![vec![]]),
            W::CastE(ref e) => e.dissatisfy(pkh_map)
        }
    }
}

impl Satisfiable for F {
    fn satisfy(
        &self,
        key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
        hash_map: &HashMap<Sha256dHash, [u8; 32]>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match *self {
            F::CheckSig(ref pk) => satisfy_checksig(pk, key_map),
            F::CheckMultiSig(k, ref keys) => satisfy_checkmultisig(k, keys, key_map),
            F::CheckSigHash(ref hash) => satisfy_checksighash(hash, key_map, pkh_map),
            F::Csv(n) => satisfy_csv(n, age),
            F::HashEqual(ref hash) => satisfy_hashequal(hash, hash_map),
            F::Threshold(k, ref sube, ref subw) => satisfy_threshold(k, sube, subw, key_map, pkh_map, hash_map, age),
            F::And(ref left, ref right) => {
                let mut ret = left.satisfy(key_map, pkh_map, hash_map, age)?;
                ret.extend(right.satisfy(key_map, pkh_map, hash_map, age)?);
                Ok(ret)
            }
            F::ParallelOr(ref left, ref right) => satisfy_parallel_or(left, right, key_map, pkh_map, hash_map, age),
            F::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, key_map, pkh_map, hash_map, age),
            F::SwitchOr(ref left, ref right) => satisfy_switch_or(left, right, key_map, pkh_map, hash_map, age),
            F::SwitchOrV(ref left, ref right) => satisfy_switch_or(left, right, key_map, pkh_map, hash_map, age),
        }
    }

    fn required_keys(&self) -> Vec<secp256k1::PublicKey> {
        match *self {
            F::CheckSig(pk) => vec![pk],
            F::CheckMultiSig(_, ref keys) => keys.clone(),
            F::CheckSigHash(..) | F::Csv(..) | F::HashEqual(..) => vec![],
            F::Threshold(_, ref sube, ref subw) => {
                let mut ret = sube.required_keys();
                for sub in subw {
                    ret.extend(sub.required_keys());
                }
                ret
            }
            F::And(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            F::ParallelOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            F::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            F::SwitchOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            F::SwitchOrV(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
        }
    }

}

impl Satisfiable for V {
    fn satisfy(
        &self,
        key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
        hash_map: &HashMap<Sha256dHash, [u8; 32]>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match *self {
            V::CheckSig(ref pk) => satisfy_checksig(pk, key_map),
            V::CheckMultiSig(k, ref keys) => satisfy_checkmultisig(k, keys, key_map),
            V::CheckSigHash(ref hash) => satisfy_checksighash(hash, key_map, pkh_map),
            V::Csv(n) => satisfy_csv(n, age),
            V::HashEqual(ref hash) => satisfy_hashequal(hash, hash_map),
            V::Threshold(k, ref sube, ref subw) => satisfy_threshold(k, sube, subw, key_map, pkh_map, hash_map, age),
            V::And(ref left, ref right) => {
                let mut ret = left.satisfy(key_map, pkh_map, hash_map, age)?;
                ret.extend(right.satisfy(key_map, pkh_map, hash_map, age)?);
                Ok(ret)
            }
            V::ParallelOr(ref left, ref right) => satisfy_parallel_or(left, right, key_map, pkh_map, hash_map, age),
            V::SwitchOr(ref left, ref right) => satisfy_switch_or(left, right, key_map, pkh_map, hash_map, age),
            V::SwitchOrT(ref left, ref right) => satisfy_switch_or(left, right, key_map, pkh_map, hash_map, age),
            V::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, key_map, pkh_map, hash_map, age),
        }
    }

    fn required_keys(&self) -> Vec<secp256k1::PublicKey> {
        match *self {
            V::CheckSig(pk) => vec![pk],
            V::CheckMultiSig(_, ref keys) => keys.clone(),
            V::CheckSigHash(..) | V::Csv(..) | V::HashEqual(..) => vec![],
            V::Threshold(_, ref sube, ref subw) => {
                let mut ret = sube.required_keys();
                for sub in subw {
                    ret.extend(sub.required_keys());
                }
                ret
            }
            V::And(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            V::ParallelOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            V::SwitchOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            V::SwitchOrT(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            V::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
        }
    }
}

impl Satisfiable for T {
    fn satisfy(
        &self,
        key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
        hash_map: &HashMap<Sha256dHash, [u8; 32]>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match *self {
            T::Csv(..) => Ok(vec![]),
            T::HashEqual(ref hash) => satisfy_hashequal(hash, hash_map),
            T::And(ref left, ref right) => {
                let mut ret = left.satisfy(key_map, pkh_map, hash_map, age)?;
                ret.extend(right.satisfy(key_map, pkh_map, hash_map, age)?);
                Ok(ret)
            }
            T::ParallelOr(ref left, ref right) => satisfy_parallel_or(left, right, key_map, pkh_map, hash_map, age),
            T::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, key_map, pkh_map, hash_map, age),
            T::CascadeOrV(ref left, ref right) => satisfy_cascade_or(left, right, key_map, pkh_map, hash_map, age),
            T::SwitchOr(ref left, ref right) => satisfy_switch_or(left, right, key_map, pkh_map, hash_map, age),
            T::SwitchOrV(ref left, ref right) => satisfy_switch_or(left, right, key_map, pkh_map, hash_map, age),
            T::CastE(ref e) => e.satisfy(key_map, pkh_map, hash_map, age),
        }
    }

    fn required_keys(&self) -> Vec<secp256k1::PublicKey> {
        match *self {
            T::Csv(..) | T::HashEqual(..) => vec![],
            T::And(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            T::ParallelOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            T::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            T::CascadeOrV(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            T::SwitchOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            T::SwitchOrV(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            T::CastE(ref sub) => sub.required_keys(),
        }
    }
}

// Helper functions to produce satisfactions for the various AST element types,
// e.g. cascade OR, parallel AND, etc., which typically do not depend on the
// specific choice of E/W/F/V/T that is chosen.

/// Computes witness size, assuming individual pushes are less than 254 bytes
fn satisfy_cost(s: &[Vec<u8>]) -> f64 {
    s.iter().map(|s| 1.0 + s.len() as f64).sum()
}

/// Helper function that produces a checksig(verify) satisfaction
fn satisfy_checksig(
    pk: &secp256k1::PublicKey,
    key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
) -> Result<Vec<Vec<u8>>, Error> {
    let secp = secp256k1::Secp256k1::without_caps();
    if let Some(sig) = key_map.get(&pk) {
        Ok(vec![sig.serialize_der(&secp)])
    } else {
        Err(Error::MissingSig(*pk))
    }
}

/// Helper function that produces a checksig(verify)hash satisfaction
fn satisfy_checksighash(
    hash: &Hash160,
    key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
    pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
) -> Result<Vec<Vec<u8>>, Error> {
    let secp = secp256k1::Secp256k1::without_caps();
    if let Some(pk) = pkh_map.get(hash) {
        if let Some(sig) = key_map.get(pk) {
            Ok(vec![
                sig.serialize_der(&secp),
                pk.serialize()[..].to_owned(),
            ])
        } else {
            Err(Error::MissingSig(*pk))
        }
    } else {
        Err(Error::MissingPubkey(*hash))
    }
}

/// Helper function that produces a checkmultisig(verify) satisfaction
fn satisfy_checkmultisig(
    k: usize,
    keys: &[secp256k1::PublicKey],
    key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
) -> Result<Vec<Vec<u8>>, Error> {
    let secp = secp256k1::Secp256k1::without_caps();
    let mut ret = Vec::with_capacity(k);
    for pk in keys {
        if let Some(sig) = key_map.get(pk) {
            ret.push(sig.serialize_der(&secp));
            if ret.len() > k {
                let max_idx = ret
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, ref sig)| sig.len())
                    .unwrap()
                    .0;
                ret.remove(max_idx);
            }
        }
    }
    if ret.len() == k {
        ret.push(vec![]);
        Ok(ret)
    } else {
        Err(Error::CouldNotSatisfy)
    }
}

fn satisfy_hashequal(
    hash: &Sha256dHash,
    hash_map: &HashMap<Sha256dHash, [u8; 32]>,
) -> Result<Vec<Vec<u8>>, Error> {
    if let Some(pre) = hash_map.get(&hash) {
        Ok(vec![pre[..].to_owned()])
    } else {
        Err(Error::MissingHash(*hash))
    }
}

fn satisfy_csv(n: u32, age: u32) -> Result<Vec<Vec<u8>>, Error> {
    if age >= n {
        Ok(vec![])
    } else {
        Err(Error::LocktimeNotMet(n))
    }
}

fn satisfy_threshold(
    k: usize,
    sube: &E,
    subw: &[W],
    key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
    pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
    hash_map: &HashMap<Sha256dHash, [u8; 32]>,
    age: u32,
) -> Result<Vec<Vec<u8>>, Error> {
    if k == 0 {
        return Ok(vec![]);
    }

    let mut satisfactions = Vec::with_capacity(1 + subw.len());
    if let Ok(sat) = sube.satisfy(key_map, pkh_map, hash_map, age) {
        satisfactions.push(sat);
    }
    for sub in subw {
        if let Ok(sat) = sub.satisfy(key_map, pkh_map, hash_map, age) {
            satisfactions.push(sat);
        }
    }
    if satisfactions.len() < k {
        return Err(Error::CouldNotSatisfy);
    }

    let mut indices: Vec<usize> = (0..satisfactions.len()).collect();
    indices.sort_by_key(|i| (1_000_000.0 * satisfy_cost(&satisfactions[*i])) as u64);

    let mut n_pushes = 0;
    for idx in indices.iter().take(k) {
        n_pushes += satisfactions[*idx].len();
    }

    let mut ret = Vec::with_capacity(n_pushes);
    for idx in indices.into_iter().take(k) {
        use std::mem;
        let obj = mem::replace(&mut satisfactions[idx], vec![]);
        ret.extend(obj);
    }
    Ok(ret)
}

fn satisfy_parallel_or(
    left: &E,
    right: &W,
    key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
    pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
    hash_map: &HashMap<Sha256dHash, [u8; 32]>,
    age: u32,
) -> Result<Vec<Vec<u8>>, Error> {
    match (
        left.satisfy(key_map, pkh_map, hash_map, age),
        right.satisfy(key_map, pkh_map, hash_map, age),
    ) {
        (Ok(mut lsat), Err(..)) => {
            let rdissat = right.dissatisfy(pkh_map)?;
            lsat.extend(rdissat);
            Ok(lsat)
        }
        (Err(..), Ok(rsat)) => {
            let mut ldissat = left.dissatisfy(pkh_map)?;
            ldissat.extend(rsat);
            Ok(ldissat)
        }
        (Err(e), Err(..)) => {
            Err(e)
        }
        (Ok(mut lsat), Ok(rsat)) => {
            let mut ldissat = left.dissatisfy(pkh_map)?;
            let rdissat = right.dissatisfy(pkh_map)?;

            if satisfy_cost(&lsat) + satisfy_cost(&rdissat) <= satisfy_cost(&rsat) + satisfy_cost(&ldissat) {
                lsat.extend(rdissat);
                Ok(lsat)
            } else {
                ldissat.extend(rsat);
                Ok(ldissat)
            }
        }
    }
}

fn satisfy_switch_or<T: Satisfiable, S: Satisfiable>(
    left: &Box<T>,
    right: &Box<S>,
    key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
    pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
    hash_map: &HashMap<Sha256dHash, [u8; 32]>,
    age: u32,
) -> Result<Vec<Vec<u8>>, Error> {
    match (
        left.satisfy(key_map, pkh_map, hash_map, age),
        right.satisfy(key_map, pkh_map, hash_map, age),
    ) {
        (Err(e), Err(..)) => Err(e),
        (Ok(mut lsat), Err(..)) => {
            lsat.push(vec![1]);
            Ok(lsat)
        }
        (Err(..), Ok(mut rsat)) => {
            rsat.push(vec![]);
            Ok(rsat)
        }
        (Ok(mut lsat), Ok(mut rsat)) => {
            if satisfy_cost(&lsat) + 2.0 <= satisfy_cost(&rsat) + 1.0 {
                lsat.push(vec![1]);
                Ok(lsat)
            } else {
                rsat.push(vec![]);
                Ok(rsat)
            }
        }
    }
}

fn satisfy_cascade_or<T: Satisfiable>(
    left: &Box<E>,
    right: &Box<T>,
    key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
    pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
    hash_map: &HashMap<Sha256dHash, [u8; 32]>,
    age: u32,
) -> Result<Vec<Vec<u8>>, Error> {
    match (
        left.satisfy(key_map, pkh_map, hash_map, age),
        right.satisfy(key_map, pkh_map, hash_map, age),
    ) {
        (Err(e), Err(..)) => Err(e),
        (Ok(lsat), Err(..)) => Ok(lsat),
        (Err(..), Ok(rsat)) => {
            let mut ldissat = left.dissatisfy(pkh_map)?;
            ldissat.extend(rsat);
            Ok(ldissat)
        }
        (Ok(lsat), Ok(rsat)) => {
            let mut ldissat = left.dissatisfy(pkh_map)?;

            if satisfy_cost(&lsat) <= satisfy_cost(&rsat) + satisfy_cost(&ldissat) {
                Ok(lsat)
            } else {
                ldissat.extend(rsat);
                Ok(ldissat)
            }
        }
    }
}
