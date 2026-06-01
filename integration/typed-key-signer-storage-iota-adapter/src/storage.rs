// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub struct IotaCompatibleKeyStorage<TInner> {
    pub inner: TInner,
}

impl<T> IotaCompatibleKeyStorage<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}
