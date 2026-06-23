# AWS KMS Adapter WASM Examples

Examples for [`@iota/aws_kms_adapter_wasm`](../).

## Prerequisites

Install dependencies:

```sh
npm install
```

Set the required environment variables:

```sh
export AWS_REGION=...
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

Integration examples additionally require:

```sh
export IOTA_IDENTITY_PKG_ID=...
export NETWORK_NAME_FAUCET=localnet  # optional, defaults to "localnet"
```

## Running examples

```sh
npm run example -- <example_name>
```

| Example name              | Description                                                   |
| ------------------------- | ------------------------------------------------------------- |
| `storage`                 | Fetch a public key from AWS KMS by key ID                     |
| `0_use_new_keys`          | Create an IOTA identity using freshly generated AWS KMS keys  |
| `1_use_existing_key`      | Create an IOTA identity using an existing AWS KMS key         |
| `2_schedule_key_deletion` | Schedule deletion of AWS KMS keys associated with an identity |
