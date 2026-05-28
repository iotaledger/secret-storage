# @iota/typed-key-signer-storage-iota-adapter-wasm

WebAssembly bindings for [typed-key-signer-storage-iota-adapter](../../../../../).

## Usage

```typescript
import { AwsKmsStorage } from "@iota/aws_kms_adapter_wasm/node/aws_kms_adapter_wasm";
import { IotaCompatibleKeyStorage, IotaCompatibleSigner } from "@iota/typed-key-signer-storage-iota-adapter-wasm/node/typed_key_signer_storage_iota_adapter_wasm";

const awsStorage = await AwsKmsStorage.fromEnv();
const keyStorage = new IotaCompatibleKeyStorage(awsStorage);

const signer = keyStorage.getSignerWithOptions(keyId, "Ed25519DerEncoded");
```

`IotaCompatibleKeyStorage` wraps any `KeyStorageTypedKeySignature` and exposes key generation, public key retrieval, and signer creation over `IotaKeySignature`. `IotaCompatibleSigner` implements the transaction signing interface for `IdentityClient`.

## Examples

See the [AWS KMS adapter integration examples](../../../../../../adapters/aws-kms-adapter/bindings/wasm/aws_kms_adapter_wasm/examples/src/1_integration) for examples that show this package in use.

## Build

```sh
npm run build
```
