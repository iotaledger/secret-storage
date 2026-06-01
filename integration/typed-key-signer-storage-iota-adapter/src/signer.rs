// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub struct IotaCompatibleSigner<T> {
    pub inner: T,
}

impl<T> IotaCompatibleSigner<T> {
    pub fn new(signer: T) -> Self {
        Self { inner: signer }
    }
}
