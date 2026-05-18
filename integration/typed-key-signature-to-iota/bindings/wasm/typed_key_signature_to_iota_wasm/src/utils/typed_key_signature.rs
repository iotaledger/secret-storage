// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use typed_key_signature::TypedKeySignature;
use secret_storage::SignatureScheme;

pub(crate) type TypedKeySignatureInput = <TypedKeySignature as SignatureScheme>::Input;
pub(crate) type TypedKeySignaturePublicKey = <TypedKeySignature as SignatureScheme>::PublicKey;
pub(crate) type TypedKeySignatureSignature = <TypedKeySignature as SignatureScheme>::Signature;
