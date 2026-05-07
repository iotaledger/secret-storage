// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use multi_signature_scheme::SignatureSchemeMulti;
use secret_storage::SignatureScheme;

pub(crate) type SignatureSchemeMultiInput = <SignatureSchemeMulti as SignatureScheme>::Input;
pub(crate) type SignatureSchemeMultiPublicKey = <SignatureSchemeMulti as SignatureScheme>::PublicKey;
pub(crate) type SignatureSchemeMultiSignature = <SignatureSchemeMulti as SignatureScheme>::Signature;
