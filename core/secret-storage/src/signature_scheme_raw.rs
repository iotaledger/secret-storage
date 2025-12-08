// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::SignatureScheme;

pub struct SignatureSchemeRaw;

impl SignatureScheme for SignatureSchemeRaw {
    type PublicKey = (Vec<u8>,);
    type Signature = (Vec<u8>,);
    type Input = (Vec<u8>,);
}
