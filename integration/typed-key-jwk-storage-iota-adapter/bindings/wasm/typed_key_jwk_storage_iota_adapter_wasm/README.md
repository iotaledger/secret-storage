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

## Build the Library

Alternatively, you can build the bindings yourself if you have Rust installed. If not, refer
to [rustup.rs](https://rustup.rs) for the installation.

### Requirements

- [Node.js](https://nodejs.org/en) (>= `v20`)
- [Rust](https://www.rust-lang.org/) (>= 1.65)
- [Cargo](https://doc.rust-lang.org/cargo/) (>= 1.65)
- for running example: a local network node with the IOTA identity package deployed as described in [Local Network Setup](https://docs.iota.org/iota-identity/getting-started/local-network-setup)

### 1. Install Local Tooling

If you want to build the library from source you have to install additional build tools locally.

### Install `wasm-bindgen-cli`

First you need to install [`wasm-bindgen-cli`](https://github.com/rustwasm/wasm-bindgen).
A manual installation is required because we use the [Weak References](https://rustwasm.github.io/wasm-bindgen/reference/weak-references.html) feature,
which [`wasm-pack` does not expose](https://github.com/rustwasm/wasm-pack/issues/930).

```bash
cargo install --force wasm-bindgen-cli
```

### Install `wasm-opt`

To reduce the size of the wasm package, it is optimized with `wasm-opt`, which is part of [`binaryen`](https://github.com/WebAssembly/binaryen).

You can either download a [release of binaryen](https://github.com/WebAssembly/binaryen/releases) and make the bin folder available in your PATH or check if your operating system tooling offers a more convenient way of installing the binaries like APT, Homebrew, etc.

Some examples:

- Linux via APT: `sudo apt-get update && sudo apt-get -y install binaryen` (taken from [here](https://installati.one/install-binaryen-ubuntu-22-04/))
- MacOS via Homebrew: `brew install binaryen` (see [Homebrew entry](https://formulae.brew.sh/formula/binaryen))

### 2. Install Dependencies

After installing `wasm-bindgen-cli`, you can install the necessary dependencies using the following command:

```bash
npm install
```

### 3. Build

You can build the bindings for `node.js` using the following command:

```bash npm2yarn
npm run build:nodejs
```
