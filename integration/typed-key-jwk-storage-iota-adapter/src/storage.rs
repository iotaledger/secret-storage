// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub struct IotaCompatibleJwkStorage<T>(pub T);

impl<T> IotaCompatibleJwkStorage<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}
