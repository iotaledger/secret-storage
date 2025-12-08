// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Result;
use crate::SignatureScheme;

pub trait KeySignTest<K: SignatureScheme, I> {
    type Signer;
    fn get_signer_test(&self, key_id: &I) -> Result<Self::Signer>;
}
