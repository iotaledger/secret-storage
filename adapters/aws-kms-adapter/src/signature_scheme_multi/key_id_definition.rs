use multi_schema::KeyIdDefinition;

use crate::AwsKmsStorage;

impl KeyIdDefinition for AwsKmsStorage {
  type KeyId = String;
}
