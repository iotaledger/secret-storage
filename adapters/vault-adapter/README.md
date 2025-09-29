# HashiCorp Vault Adapter

This adapter provides integration between IOTA Secret Storage and HashiCorp Vault for enterprise-grade key management and cryptographic operations.

## Features

- **ECDSA P-256 Key Generation**: Create secp256r1 keys using Vault's Transit secrets engine
- **Secure Signing**: Sign data using keys stored securely in Vault
- **Key Management**: Full lifecycle management (create, retrieve, delete)
- **Environment Configuration**: Simple configuration via environment variables
- **Enterprise-Ready**: Integrates with Vault's authentication, audit logging, and policy systems

## Prerequisites

- HashiCorp Vault server (development or production)
- Transit secrets engine enabled
- Valid Vault authentication token

## Quick Start

### 1. Start Vault Development Server

```bash
# Using the provided script
./scripts/vault-dev.sh start

# Or using Docker Compose
docker-compose -f docker-compose.vault.yml up -d
```

### 2. Set Environment Variables

```bash
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="dev-token"
export VAULT_MOUNT_PATH="transit"  # optional, defaults to "transit"
```

### 3. Run Examples

```bash
# Basic usage example
cargo run --package vault-adapter --example basic_usage

# Comprehensive signing demo
cargo run --package vault-adapter --example signing_demo
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `VAULT_ADDR` | Vault server address | - | Yes |
| `VAULT_TOKEN` | Authentication token | - | Yes |
| `VAULT_MOUNT_PATH` | Transit engine mount path | `transit` | No |

### Programmatic Configuration

```rust
use vault_adapter::{VaultConfig, VaultStorage};

// From environment variables
let storage = VaultStorage::from_env().await?;

// Explicit configuration
let config = VaultConfig::new(
    "http://localhost:8200".to_string(),
    "dev-token".to_string(),
    Some("transit".to_string())
);
let storage = VaultStorage::new(config).await?;
```

## Usage Examples

### Basic Key Operations

```rust
use vault_adapter::{VaultStorage, VaultKeyOptions};
use secret_storage_core::{KeyGenerate, KeySign, KeyDelete, Signer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage
    let storage = VaultStorage::from_env().await?;

    // Generate a new key
    let options = VaultKeyOptions {
        description: Some("My signing key".to_string()),
        key_name: Some("my-key".to_string()),
    };
    let (key_id, public_key) = storage.generate_key_with_options(options).await?;

    // Sign data
    let signer = storage.get_signer(&key_id)?;
    let signature = signer.sign(&b"Hello, World!".to_vec()).await?;

    // Clean up
    storage.delete(&key_id).await?;

    Ok(())
}
```

### Using Storage Factory

```rust
use storage_factory::StorageBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = StorageBuilder::new()
        .vault()
        .with_vault_addr("http://localhost:8200".to_string())
        .with_vault_token("dev-token".to_string())
        .build_vault()
        .await?;

    // Use storage...
    Ok(())
}
```

## Architecture

The Vault adapter follows the hexagonal architecture pattern:

```
┌─────────────────────┐
│   Storage Factory   │ (Application Layer)
└──────────┬──────────┘
           │
┌─────────────────────┐
│   Vault Adapter     │ (Adapter Layer)
├─────────────────────┤
│ - VaultStorage      │
│ - VaultSigner       │ 
│ - VaultConfig       │
└──────────┬──────────┘
           │
┌─────────────────────┐
│ Secret Storage Core │ (Core Layer)
├─────────────────────┤
│ - KeyGenerate       │
│ - KeySign           │
│ - KeyDelete         │
│ - Signer            │
└─────────────────────┘
```

## Security Considerations

- **Key Isolation**: Private keys never leave Vault's secure boundary
- **Encryption at Rest**: All keys are encrypted using Vault's encryption-at-rest
- **Audit Logging**: All operations are logged through Vault's audit system
- **Access Control**: Leverage Vault's policy system for fine-grained permissions
- **Network Security**: Use TLS in production environments

## Production Deployment

### Required Vault Policies

```hcl
# Transit policy for key operations
path "transit/keys/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "transit/sign/*" {
  capabilities = ["update"]
}

path "transit/verify/*" {
  capabilities = ["update"]  
}
```

### Production Configuration

```bash
# Production environment variables
export VAULT_ADDR="https://vault.company.com:8200"
export VAULT_TOKEN="$(vault auth -method=aws)"  # or other auth method
export VAULT_MOUNT_PATH="iota-transit"
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   ```
   Error: Http(reqwest::Error { kind: Request, ... })
   ```
   - Verify `VAULT_ADDR` is correct
   - Ensure Vault server is running
   - Check network connectivity

2. **Permission Denied**
   ```
   Error: Api("HTTP 403: permission denied")
   ```
   - Verify `VAULT_TOKEN` is valid
   - Check Vault policies allow required operations
   - Ensure Transit engine is enabled

3. **Transit Engine Not Found**
   ```
   Error: Api("HTTP 404: ...")
   ```
   - Enable Transit secrets engine: `vault secrets enable transit`
   - Verify `VAULT_MOUNT_PATH` matches enabled path

### Debugging

Enable debug logging:

```bash
export RUST_LOG=vault_adapter=debug
cargo run --package vault-adapter --example basic_usage
```

## Development

### Running Tests

```bash
# Unit tests
cargo test --package vault-adapter

# Integration tests (requires running Vault)
./scripts/vault-dev.sh start
cargo test --package vault-adapter -- --ignored
```

### Local Development Setup

```bash
# Start Vault development server
./scripts/vault-dev.sh start

# Check status
./scripts/vault-dev.sh status

# View logs
./scripts/vault-dev.sh logs

# Clean up
./scripts/vault-dev.sh clean
```

## Contributing

1. Follow the existing code style and patterns
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all examples compile and run
5. Test with both development and production Vault configurations

## License

Apache-2.0 - See [LICENSE](../../LICENSE) for details.