# Cryptographic Key Store Library

This library offers a comprehensive solution for storing cryptographic keys within Rust applications. It provides a set of traits for creating, signing, deleting, checking the existence of, and retrieving cryptographic keys. This versatility makes it an essential tool for secure key management.

The library aims to establish a lightweight standardization layer without introducing any opinionated solutions for key management. It leverages the flexibility of the Iota (Sui) SDK, allowing the separation of the signing process from the SDK flow. This separation offers a significant advantage for users with existing complex key management solutions, facilitating easier integration and use.

## Features

- **Key Creation**: Easily generate new cryptographic keys.
- **Key Signing**: Use keys for signing operations.
- **Key Deletion**: Securely delete keys when they are no longer needed.
- **Key Existence Check**: Verify the presence of keys in the storage.
- **Key Retrieval**: Access keys for cryptographic operations.

## Security aspect

The library promotes the following security concepts:

### Enclave principle

The enclave principle in key management refers to the use of secure, isolated environments (enclaves) for the management and protection of cryptographic keys. These enclaves provide a trusted execution environment (TEE) where sensitive operations can be performed securely, even on potentially compromised or untrusted systems.

**Implementation**: The interfaces are designed with the assumption that private keys cannot be generated or stored outside secure enclaves.

### Least privilege principle

  The system should have only the minimal set of permissions necessary to perform its intended function. This principle aims to reduce the potential damage that could occur if a user, process, or program is compromised or misbehaves.

**Implementation**: The library specifies atomic 'permissions' such as `KeyRead`, `KeySign`, etc., allowing only the features actually used by the library. This approach prevents alternative, potentially insecure paths from being available to the user.

### Explicit boundaries principle

The explicit Boundaries principle involves defining clear and explicit interfaces that separate the provider's code from the user's code. These boundaries ensure that there is a clear contract regarding how the provider's code should be used and what responsibilities it assumes.

**Implementation**: The interface definitions clarify the boundaries between user code and provider code, emphasizing the importance of responsibility for damages caused by insecure code.

## Getting Started

### Prerequisites

This library is built with Rust, so you'll need Rust and Cargo installed on your system. You can install them from [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).

### Installation

To use this library in your project, add it as a dependency in your `Cargo.toml` file:

```toml
[dependencies]
secret-storage = { git="https://github.com/iotaledger/secret-storage"}
```

#### Feature flags

`transaction_helpers` - enables the dependency on IOTA SDK and introduce useful abstractions for signing
the transaction payload

```toml
[dependencies]
secret-storage =  { version = "https://github.com/iotaledger/secret-storage", features="transaction_utils"}

```

## Usage

The example shows how the secret storage interface can be used when signing the `TransactionData` from [IOTA-SDK](https://github.com/iotaledger/iota):

```rust
struct ExampleSdkTypes {}
impl KeySignatureTypes for ExampleSdkTypes {
    type PublicKey = String;
    type Signature = Signature;
}

async fn using_signer(
    client: SuiClient,
    kms: impl KeysStorage<ExampleSdkTypes, KeyID = String>,
) -> Result<()> {
    // Define the account address and module address
    let account_address = SuiAddress::from_str("").expect("account address must be valid");
    let module_address = ObjectID::from_str("").expect("object id must be valid");

    // Transaction builder creates a transaction data.
    // In this case, the transaction calls the `create_new_trail_and_own`` from `trails` module
    let transaction_data = client
        .transaction_builder()
        .move_call(
            account_address,
            module_address,
            "trail",
            "create_new_trail_and_own",
            vec![],
            vec![SuiJsonValue::new(json!("data")).context("failed to serialize immutable data")?],
            None,
            1000000000,
            None,
        )
        .await
        .context("failed building transaction data for creating new trail and owning it");

    // Obtaining the signer from the kms for specific key_id
    let signer = kms.get_signer("key_id").expect("key not found");

    // Sign the transaction data
    let signature = signer
        .sign(transaction_data.get_data_to_sign())
        .await
        .unwrap();

    // Create a Transaction that includes the TransactionData and the Signature
    let transaction = Transaction::from_data(transaction_data, vec![signature]);

    // Send Transaction to using the sdk client
    let transaction_block_response = client
        .quorum_driver_api()
        .execute_transaction_block(transaction, Default::default, None)
        .await
        .context("failed to execute transaction block")?;

    Ok(())
}
```

## Contributing

Contributions are welcome! Feel free to open pull requests or issues to suggest improvements or add new features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact
