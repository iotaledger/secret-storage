# @iota/typed-key-jwk-storage-iota-adapter-wasm

WebAssembly bindings for [typed-key-jwk-storage-iota-adapter](../../../../../).

## Usage

```typescript
import { AwsKmsStorage } from "@iota/aws_kms_adapter_wasm/node/aws_kms_adapter_wasm";
import { IotaCompatibleJwkStorage } from "@iota/typed-key-jwk-storage-iota-adapter-wasm/node/typed_key_jwk_storage_iota_adapter_wasm";

const awsStorage = await AwsKmsStorage.fromEnv();
const jwkStorage = new IotaCompatibleJwkStorage(awsStorage);
```

`IotaCompatibleJwkStorage` implements `JwkStorage` and can be passed directly to the IOTA identity SDK.

## Examples

See the [AWS KMS adapter integration examples](../../../../../../adapters/aws-kms-adapter/bindings/wasm/aws_kms_adapter_wasm/examples/src/1_integration) for examples that show this package in use.

## Build

```sh
npm run build
```
