# aws-kms-adapter

AWS KMS backend for [secret-storage](../../core/secret-storage) core traits.

Implements `KeyGenerate`, `KeyGet`, `KeySignWithOptions`, `KeyDelete`, and `KeyExist` against AWS Key Management Service via `AwsKmsStorage`. Keys never leave the KMS HSM.

`AwsKmsStorage::get_signer_with_options` returns an `AwsKmsSigner` that implements `Signer<TypedKeySignature>`.

## Supported key types

| `KeyType` variant | Algorithm | AWS KeySpec             |
| ----------------- | --------- | ----------------------- |
| `Ed25519`         | EdDSA     | `ECC_NIST_EDWARDS25519` |
| `Secp256r1`       | ES256     | `ECC_NIST_P256`         |
| `Secp256k1`       | ES256K    | `ECC_SECG_P256K1`       |

## Configuration

Authentication via environment variables:

```sh
AWS_REGION=eu-west-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

Or via a named AWS profile:

```sh
AWS_PROFILE=my-profile
```

## Bindings

- [WASM](bindings/wasm/aws_kms_adapter_wasm) - TypeScript/JavaScript wrapper
