use typed_key_signature::KeyIdDefinition;

use crate::AwsKmsStorage;

impl KeyIdDefinition for AwsKmsStorage {
  type KeyId = String;
}
