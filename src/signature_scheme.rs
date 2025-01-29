// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// [`SignatureScheme`] is a trait that defines the public key and signature types.
pub trait SignatureScheme {
    type PublicKey;
    type Signature;
    type Input;
}
