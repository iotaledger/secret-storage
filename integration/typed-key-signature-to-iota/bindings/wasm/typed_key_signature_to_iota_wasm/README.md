# @iota/typed-key-signature-to-iota-wasm

WebAssembly bindings for [typed-key-signature-to-iota](../../../../../).

## Usage

```typescript
import { AwsKmsStorage } from "@iota/aws_kms_adapter_wasm/node/aws_kms_adapter_wasm";
import { IotaCompatibleKeyStorage, IotaCompatibleSigner } from "@iota/typed-key-signature-to-iota-wasm/node/typed_key_signature_to_iota_wasm";

const awsStorage = await AwsKmsStorage.fromEnv();
const iotaStorage = new IotaCompatibleKeyStorage(awsStorage);

const rawSigner = awsStorage.getSignerWithOptions(keyId, "Ed25519DerEncoded");
const signer = new IotaCompatibleSigner(rawSigner);
```

`IotaCompatibleKeyStorage` implements `JwkStorage` and can be passed directly to the IOTA identity SDK. `IotaCompatibleSigner` implements the transaction signing interface for `IdentityClient`.

## Build

```sh
npm run build
```
