# IOTA Secret Storage - Refactored Architecture

A flexible and secure key storage ecosystem for IOTA Trust Framework, following hexagonal architecture principles with modular adapters for different key management strategies.

## 🏗️ Architecture Overview

This repository implements a multi-layered approach to key management:

- **Core Domain**: Pure business logic and trait definitions
- **Adapters**: Infrastructure implementations (AWS KMS, file system, passkey, etc.)
- **Applications**: Use case orchestration and adapter selection

## 📁 Repository Structure

```
secret-storage/
├── core/
│   └── secret-storage/              # Core traits and types
├── adapters/                        # Infrastructure adapters
│   └── aws-kms-adapter/            # AWS KMS implementation
├── applications/                    # Application layer
│   └── storage-factory/            # Builder pattern for adapter selection
├── .env.example                    # Environment variables template
└── README.md
```

## 🚀 Quick Start

### 1. AWS Configuration Setup

For detailed AWS setup instructions, see [AWS Setup Guide](README-AWS.md).

Quick configuration options:

**Option 1: AWS Profile (Recommended)**
```bash
export AWS_PROFILE=your-profile-name
export AWS_REGION=eu-west-1
```

**Option 2: Direct Credentials**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=eu-west-1
```

### 2. Run IOTA KMS Demo

```bash
AWS_REGION=eu-west-1 AWS_PROFILE=your-profile cargo run --package storage-factory --example iota_kms_demo
```

This demo will:
- Generate a new KMS key with dynamic alias
- Create an IOTA address from the public key
- Request testnet funds via faucet
- Sign and submit an IOTA transaction

### 3. Manual Adapter Configuration

```rust
use storage_factory::StorageBuilder;

// Explicit AWS KMS configuration
let storage = StorageBuilder::new()
    .aws_kms()
    .with_region("eu-west-1".to_string())
    .build_aws_kms()
    .await?;
```

## 🔧 AWS Authentication

The code supports both authentication methods:

**Method 1: AWS Profile (Recommended)**
```bash
AWS_PROFILE=your-profile-name
AWS_REGION=eu-west-1
```

**Method 2: Direct Credentials**
```bash
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=eu-west-1
```

The `StorageBuilder` automatically detects which method is available:
- If `AWS_PROFILE` is set, uses profile-based authentication
- Otherwise, uses direct credentials from environment variables

See [AWS Setup Guide](README-AWS.md) for detailed configuration instructions.

For comprehensive architecture documentation, see [Technical Documentation](doc/documentation.en.md).
```


## 📋 Examples

### IOTA KMS Demo (Main Example)

```bash
AWS_REGION=eu-west-1 AWS_PROFILE=your-profile cargo run --package storage-factory --example iota_kms_demo
```

## 🔍 Implemented Features

### ✅ Core Traits
- [x] `KeyGenerate` - Generate new key pairs
- [x] `KeySign` - Sign data with stored keys
- [x] `KeyDelete` - Delete keys (schedule deletion for AWS KMS)
- [x] `KeyExist` - Check key existence
- [x] `KeyGet` - Retrieve public keys
- [x] `Signer` - Low-level signing interface

### ✅ AWS KMS Adapter
- [x] Environment-based configuration
- [x] Key generation with ECC_NIST_P256 (default)
- [x] ECDSA_SHA_256 signatures
- [x] Key existence checking
- [x] Public key retrieval
- [x] Scheduled key deletion
- [x] IAM integration
- [x] CloudTrail audit support

### ✅ Builder Pattern
- [x] Auto-detection of available adapters
- [x] Manual adapter configuration
- [x] Environment-based selection
- [x] Extensible for future adapters

### ✅ Testing Infrastructure
- [x] Unit tests for all components
- [x] Integration tests with AWS KMS
- [x] LocalStack support for local testing
- [x] Mock implementations for development

## 🔮 Future Adapters

The architecture supports additional adapters:

- **File System Storage** - For development and testing
- **Passkey Integration** - Client-side self-custody
- **DFNS Service** - Multi-party computation
- **Azure Key Vault** - Microsoft cloud HSM
- **Google Cloud KMS** - Google cloud key management
- **Hardware Security Modules** - Direct HSM integration

## 🔒 Security Considerations

- **Private keys never leave secure environments** (KMS, HSM, enclaves)
- **Minimum required permissions** via IAM policies
- **Audit logging** through CloudTrail
- **Environment variable validation**
- **Secure error handling** without key material exposure

## 💼 Enterprise Features

### Enclave Principle
The interfaces are designed with the assumption that private keys cannot be generated or stored outside secure enclaves.

### Least Privilege Principle
The system provides atomic 'permissions' such as `KeyRead`, `KeySign`, etc., allowing only the features actually used by the application.

### Explicit Boundaries Principle
Clear interface definitions separate provider code from user code, emphasizing responsibility boundaries.

## 🤝 Contributing

1. Follow the hexagonal architecture principles
2. All comments must be in English
3. Implement comprehensive tests for new adapters
4. Update documentation for new features
5. Follow existing code style and conventions

## 📜 License

Apache-2.0

## 🏢 Enterprise Roadmap

- **Multi-tenancy support** (planned)
- **Key rotation mechanisms** (planned)  
- **Compliance reporting** (planned)
- **Performance monitoring** (planned)
- **Policy engines** (planned)

---

## 📚 Additional Documentation

- [AWS Setup Guide](README-AWS.md) - Complete AWS KMS configuration instructions
- [Technical Documentation](doc/documentation.en.md) - Hexagonal architecture and adapter details
- [Signature Documentation](doc/signature.en.md) - IOTA signature format specifications