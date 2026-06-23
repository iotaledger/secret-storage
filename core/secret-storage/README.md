# secret-storage

Core traits for flexible, modular key storage and signing.

## Traits

| Trait                | Description                           |
| -------------------- | ------------------------------------- |
| `Signer`             | Sign data with a key held in storage  |
| `KeyGenerate`        | Generate a new key pair               |
| `KeyGet`             | Retrieve the public key for a key ID  |
| `KeySign`            | Sign data using a stored key          |
| `KeySignWithOptions` | Sign with additional per-call options |
| `KeyDelete`          | Delete or schedule deletion of a key  |
| `KeyExist`           | Check whether a key ID exists         |
| `KeysStorage`        | Convenience combination of the above  |

See [root README.md](../../README.md) for context.
