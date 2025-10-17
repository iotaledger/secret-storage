# IOTA Secret Storage - Refactored Architecture

A flexible and secure key storage ecosystem for IOTA Trust Framework, following hexagonal architecture principles with modular adapters for different key management strategies.

## 🏗️ Architecture Overview

This repository implements a multi-layered approach to key management:

- **Core Domain**: Pure business logic and trait definitions
- **Adapters**: Infrastructure implementations (AWS KMS, HashiCorp Vault, file system, etc.)
- **Applications**: Use case orchestration and adapter selection

## 📁 Repository Structure

```
secret-storage/
├── core/
│   └── secret-storage/              # Core traits and types
├── adapters/                        # Infrastructure adapters
│   ├── aws-kms-adapter/            # AWS KMS implementation
│   └── vault-adapter/              # HashiCorp Vault implementation
├── applications/                    # Application layer
│   └── storage-factory/            # Builder pattern for adapter selection
├── .env.example                    # Environment variables template
└── README.md
```

## 🚀 Quick Start

### Option A: AWS KMS

#### 1. AWS Configuration Setup

For detailed AWS setup instructions, see [AWS Integration Guide](AWS_INTEGRATION.md).

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

#### 2. Run IOTA KMS Demo

```bash
AWS_REGION=eu-west-1 AWS_PROFILE=your-profile cargo run --package storage-factory --example iota_kms_demo
```

This demo will:
- Generate a new KMS key with dynamic alias
- Create an IOTA address from the public key
- Request testnet funds via faucet
- Sign and submit an IOTA transaction

### Option B: HashiCorp Vault

#### 1. Start Vault Server

```bash
# Start Vault with Docker Compose
docker-compose -f docker-compose.vault.yml up -d

# Set environment variables
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="dev-token"
export VAULT_MOUNT_PATH="transit"
```

#### 2. Run IOTA Vault Demo

```bash
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-token VAULT_MOUNT_PATH="transit" cargo run --package storage-factory --example iota_vault_demo
```

This demo will:
- Generate a new Vault ECDSA P-256 key with dynamic identifier
- Create an IOTA address from the public key
- Request testnet funds via faucet (~10 IOTA)
- Sign and submit an IOTA transaction to testnet

### Manual Adapter Configuration

```rust
use storage_factory::StorageBuilder;

// Explicit AWS KMS configuration
let storage = StorageBuilder::new()
    .aws_kms()
    .with_region("eu-west-1".to_string())
    .build_aws_kms()
    .await?;

// HashiCorp Vault configuration
let storage = StorageBuilder::new()
    .vault()
    .build_vault()
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

See [AWS Integration Guide](AWS_INTEGRATION.md) for detailed configuration instructions.

## 🔧 HashiCorp Vault Authentication

### Standard Mode (Development/Direct Connection)

For HashiCorp Vault, set the following environment variables:

```bash
VAULT_ADDR="http://localhost:8200"     # Vault server address
VAULT_TOKEN="dev-token"                # Vault authentication token
VAULT_MOUNT_PATH="transit"             # Transit secrets engine mount path (optional, defaults to "transit")
```

### Vault Agent Sidecar Mode (Kubernetes - Recommended for Production)

For Kubernetes deployments, use the Vault Agent sidecar pattern for enhanced security:

```bash
VAULT_ADDR="http://127.0.0.1:8100"     # Local Vault Agent proxy
VAULT_AGENT_MODE="true"                # Enable agent mode (no VAULT_TOKEN needed!)
VAULT_MOUNT_PATH="transit"             # Transit secrets engine mount path (optional)
```

**Benefits:**
- ✅ No long-lived secrets in pods
- ✅ Automatic token rotation (e.g., TTL 1h)
- ✅ ServiceAccount-based authentication
- ✅ Reduced attack surface

For complete Kubernetes setup with Vault Agent sidecar, see the [Vault Integration Guide](VAULT_INTEGRATION.md).

The `StorageBuilder` automatically detects Vault configuration from environment variables.

For comprehensive architecture documentation, see [Technical Documentation](doc/documentation.en.md).


## 📋 Examples

### AWS KMS Examples

**IOTA KMS Demo (Complete workflow)**
```bash
AWS_REGION=eu-west-1 AWS_PROFILE=your-profile cargo run --package storage-factory --example iota_kms_demo
```

### HashiCorp Vault Examples

**IOTA Vault Demo (Complete workflow)**
```bash
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-token VAULT_MOUNT_PATH="transit" cargo run --package storage-factory --example iota_vault_demo
```

**Basic Vault Usage**
```bash
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-token VAULT_MOUNT_PATH="transit" cargo run --package vault-adapter --example basic_usage
```

**Vault Agent Sidecar Mode (Kubernetes)**
```bash
VAULT_ADDR=http://127.0.0.1:8100 VAULT_AGENT_MODE=true cargo run --package vault-adapter --example vault_agent_mode
```

## 🔍 Implemented Features

### ✅ Core Traits
- [x] `KeyGenerate` - Generate new key pairs
- [x] `KeySign` - Sign data with stored keys
- [x] `KeyDelete` - Delete keys (schedule deletion for AWS KMS)
- [x] `KeyExist` - Check key existence
- [x] `KeyGet` - Retrieve public keys
- [x] `Signer` - Low-level signing interface

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

- **File System Storage** (For development and testing)
- **DFNS Service** 
- **Turnkey Service** 

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

## 📜 License

Apache-2.0

---

## 📚 Additional Documentation

- [AWS Setup Guide](AWS_INTEGRATION.md) - Complete AWS KMS configuration instructions
- [Vault Integration Guide](VAULT_INTEGRATION.md) - Complete HashiCorp Vault setup and integration (includes Kubernetes deployment)
- [Technical Documentation](doc/documentation.en.md) - Hexagonal architecture and adapter details