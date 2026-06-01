// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use secret_storage::SignatureScheme;

use crate::TypedKeySignaturePublicKey;
use crate::TypedKeySignatureSignature;

pub struct TypedKeySignature;

impl SignatureScheme for TypedKeySignature {
    type PublicKey = TypedKeySignaturePublicKey;
    type Signature = TypedKeySignatureSignature;
    type Input = Vec<u8>;
}
