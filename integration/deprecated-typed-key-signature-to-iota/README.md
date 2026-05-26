# typed-key-signature-to-iota

Bridges [typed-key-signature](../typed-key-signature) storage backends to the IOTA identity SDK.

## Components

**`IotaCompatibleKeyStorage`** - wraps any `typed-key-signature` storage and implements `JwkStorage` from `identity_iota`. Use it wherever the identity SDK expects a `JwkStorage`.

**`IotaCompatibleSigner`** - wraps any `Signer<TypedKeySignature>` and implements `Signer<IotaKeySignature>`. Use it to build an `IdentityClient`.

## Bindings

- [WASM](bindings/wasm/typed_key_signature_to_iota_wasm) - TypeScript/JavaScript wrapper
