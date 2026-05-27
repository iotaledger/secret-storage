# typed-key-signer-storage-iota-adapter

Bridges [typed-key-signature](../typed-key-signature) signers to the IOTA interaction SDK's transaction signing interface.

## Components

**`IotaCompatibleKeyStorage`** - wraps any `typed-key-signature` storage and implements `secret-storage` key storage traits over `IotaKeySignature`.

**`IotaCompatibleSigner`** - wraps any `Signer<TypedKeySignature>` and implements `Signer<IotaKeySignature>`. Use it to build an `IdentityClient`.

## Bindings

- [WASM](bindings/wasm/typed_key_signer_storage_iota_adapter_wasm) - TypeScript/JavaScript wrapper
