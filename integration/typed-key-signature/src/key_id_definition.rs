pub trait KeyIdDefinition {
    type KeyId: TryFrom<String> + Into<String> + Send;
}
