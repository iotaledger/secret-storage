# typed-key-jwk-storage-iota-adapter

Bridges [typed-key-signature](../typed-key-signature) storage backends to the IOTA identity SDK's `JwkStorage` interface.

## Components

**`IotaCompatibleJwkStorage`** - wraps any `typed-key-signature` storage and implements `JwkStorage` from `identity_iota`. Use it wherever the identity SDK expects a `JwkStorage`.

## Bindings

- [WASM](bindings/wasm/typed_key_jwk_storage_iota_adapter_wasm) - TypeScript/JavaScript wrapper
