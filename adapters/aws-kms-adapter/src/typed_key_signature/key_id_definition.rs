// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use typed_key_signature::KeyIdDefinition;

use crate::AwsKmsStorage;

impl KeyIdDefinition for AwsKmsStorage {
  type KeyId = String;
}
