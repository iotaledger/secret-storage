use multi_signature_scheme::KeyIdDefinition;

use crate::AwsKmsStorage;

impl KeyIdDefinition for AwsKmsStorage {
  type KeyId = String;
}
