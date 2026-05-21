# @iota/aws_kms_adapter_wasm

WebAssembly bindings for [aws-kms-adapter](../../../../../).

## Usage

```typescript
import { AwsKmsStorage } from "@iota/aws_kms_adapter_wasm/node/aws_kms_adapter_wasm";

const storage = await AwsKmsStorage.create(region, accessKeyId, secretAccessKey, sessionToken);
```

## Build

```sh
npm run build
```
