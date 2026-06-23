// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub trait KeyIdDefinition {
    type KeyId: TryFrom<String> + Into<String> + Send;
}
