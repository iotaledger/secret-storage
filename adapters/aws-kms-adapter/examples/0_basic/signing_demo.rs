// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Demonstrates message signing with AWS KMS using a secp256r1 key.
//!
//! Usage:
//! ```
//! AWS_PROFILE=<profile> AWS_REGION=<region> cargo run --example signing_demo
//! ```

use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::KeySpec;
use examples::create_storage;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions;
use secret_storage::Signer;
use typed_key_signature::KeyType;
use typed_key_signature::TypedKeySignaturePublicKey;
use typed_key_signature::TypedKeySignatureSignature;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = create_storage().await?.with_key_options(AwsKmsKeyOptions {
        description: Some("IOTA Demo - secp256r1 signing key".to_string()),
        policy: None,
        tags: vec![
            ("Project".to_string(), "IOTA-SecretStorage".to_string()),
            ("Purpose".to_string(), "SigningDemo".to_string()),
        ],
        key_spec: Some(KeySpec::EccNistP256),
    });

    let (key_id, _) = storage.generate_key_with_options(KeyType::Secp256r1DerEncoded).await?;
    println!("Generated key: {key_id}");

    let signer = storage.get_signer_with_options(&key_id, &KeyType::Secp256r1DerEncoded)?;

    let messages: Vec<Vec<u8>> = vec![
        b"Hello, IOTA Secret Storage!".to_vec(),
        b"Short msg".to_vec(),
        b"This is a longer message that we want to sign using AWS KMS and secp256r1 elliptic curve cryptography. The signature will be generated securely within the AWS KMS hardware security module.".to_vec(),
        vec![0u8; 32],
        (0u8..=255).collect(),
    ];

    for (i, message) in messages.iter().enumerate() {
        let signature: TypedKeySignatureSignature = signer.sign(message).await?;
        let sig_bytes = signature.bytes();
        println!(
            "Message #{} ({} bytes) => {} byte signature ({}...)",
            i + 1,
            message.len(),
            sig_bytes.len(),
            hex::encode(&sig_bytes[..sig_bytes.len().min(8)]),
        );
    }

    let signer_pk: TypedKeySignaturePublicKey = signer.public_key().await?;
    let storage_pk = storage.public_key(&key_id).await?;
    if signer_pk.bytes() != storage_pk.bytes() {
        return Err("Public key mismatch between signer and storage".into());
    }
    println!("Public key consistent between signer and storage.");

    // Key not deleted — reuse with: AWS_KEY_ID={key_id}
    println!("Key preserved: {key_id}");

    Ok(())
}
