// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod error;
mod signature_scheme;
mod signer;
mod storage;

pub use error::*;
pub use signature_scheme::*;
pub use signer::*;
pub use storage::*;

#[derive(Debug)]
pub struct Jwk;

pub trait ToJwk {
    fn to_jwk(&self) -> Jwk;
}

pub struct SignatureVerificationError;

pub trait PublicKey: ToJwk {
    type Signature: Signature<VerifyingKey = Self>;

    const LEN: usize;
    fn as_bytes(&self) -> &[u8];
    fn verify(&self, data: &[u8], signature: &Self::Signature) -> Result<(), SignatureVerificationError>;
}

pub trait Signature {
    type VerifyingKey: PublicKey;
    const LEN: usize;

    fn as_bytes(&self) -> &[u8];
}

/// Sync signer trait, used internally to implement our async signer trait.
pub trait SecretKey: ToJwk {
    type Signature: Signature;

    const LEN: usize;
    fn as_bytes(&self) -> &[u8];
    // COMMENT: I think this doesn't need to be fallible. Most crates' sync sign functions don't return errors.
    // e.g. [ed25519-compact](https://docs.rs/ed25519-compact/latest/ed25519_compact/struct.SecretKey.html#method.sign)
    fn sign(&self, data: &[u8]) -> Self::Signature;
}
