# typed-key-signature

A `SignatureScheme` implementation that carries key type metadata alongside the signature bytes.

`TypedKeySignature` attaches a `KeyType` tag to public keys and signatures so that storage and signing code can branch on the key algorithm without out-of-band information.

## Key types

| `KeyType` variant     | Curve                    |
| --------------------- | ------------------------ |
| `Ed25519DerEncoded`   | Ed25519 (DER-encoded)    |
| `Secp256r1DerEncoded` | NIST P-256 (DER-encoded) |
| `Secp256k1DerEncoded` | secp256k1 (DER-encoded)  |

## Related crates

- [secret-storage](../../core/secret-storage) - core traits
- [aws-kms-adapter](../../adapters/aws-kms-adapter) - implements the traits for AWS KMS
- [typed-key-signature-to-iota](../typed-key-signature-to-iota) - bridges to the IOTA identity SDK
