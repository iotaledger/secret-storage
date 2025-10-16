# HashiCorp Vault Adapter

This adapter provides integration between IOTA Secret Storage and HashiCorp Vault for enterprise-grade key management and cryptographic operations.

## Features

- **ECDSA P-256 Key Generation**: Create secp256r1 keys using Vault's Transit secrets engine
- **Secure Signing**: Sign data using keys stored securely in Vault
- **Key Management**: Full lifecycle management (create, retrieve, delete)
- **Environment Configuration**: Simple configuration via environment variables
- **Enterprise-Ready**: Integrates with Vault's authentication, audit logging, and policy systems

## Prerequisites

- HashiCorp Vault server v1.20+ (development or production)
- Transit secrets engine enabled
- Valid Vault authentication token

## Quick Start

### 1. Start Vault Development Server

```bash
# Using Docker Compose
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
| `VAULT_TOKEN` | Authentication token | - | No* |
| `VAULT_MOUNT_PATH` | Transit engine mount path | `transit` | No |
| `VAULT_AGENT_MODE` | Enable Vault Agent sidecar mode | `false` | No |

\* `VAULT_TOKEN` is not required when `VAULT_AGENT_MODE=true`

### Standard Configuration (Direct Connection)

```bash
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="dev-token"
export VAULT_MOUNT_PATH="transit"  # optional, defaults to "transit"
```

### Vault Agent Sidecar Configuration (Kubernetes)

```bash
# App connects to local Vault Agent proxy
export VAULT_ADDR="http://127.0.0.1:8100"
export VAULT_AGENT_MODE="true"
# No VAULT_TOKEN needed - injected automatically by agent
export VAULT_MOUNT_PATH="transit"  # optional
```

### Programmatic Configuration

```rust
use vault_adapter::{VaultConfig, VaultStorage};

// From environment variables
let storage = VaultStorage::from_env().await?;

// Standard configuration with token
let config = VaultConfig::new(
    "http://localhost:8200".to_string(),
    "dev-token".to_string()
);
let storage = VaultStorage::new(config).await?;

// Vault Agent sidecar mode
let config = VaultConfig::new_agent_mode(
    "http://127.0.0.1:8100".to_string()
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
- **Vault Agent Pattern**: In Kubernetes, use Vault Agent sidecar for automatic token management

## Kubernetes Deployment with Vault Agent Sidecar

### Overview

The Vault Agent sidecar pattern provides secure, zero-configuration authentication in Kubernetes:

1. **Vault Agent** authenticates using the pod's ServiceAccount token
2. Opens a local proxy on `127.0.0.1:8100`
3. Automatically injects `X-Vault-Token` header in all requests
4. Handles token renewal and rotation automatically

### Benefits

- ✅ No long-lived secrets in pods
- ✅ Automatic token rotation (e.g., TTL 1h)
- ✅ Reduced attack surface
- ✅ Native Kubernetes authentication
- ✅ Zero secret management in application code

### Vault Agent Configuration

Create `vault-agent-config.hcl`:

```hcl
# Auto-authentication using Kubernetes ServiceAccount
auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role = "iota-app"
    }
  }
  
  sink "file" {
    config = {
      path = "/vault/secrets/token"
    }
  }
}

# API proxy with automatic token injection
api_proxy {
  use_auto_auth_token = true
}

# Local listener for app connections
listener "tcp" {
  address = "127.0.0.1:8100"
  tls_disable = true
}

# Vault server address
vault {
  address = "https://vault.company.com:8200"
}
```

### Kubernetes Deployment YAML

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iota-app
  namespace: iota
spec:
  replicas: 1
  selector:
    matchLabels:
      app: iota-app
  template:
    metadata:
      labels:
        app: iota-app
    spec:
      serviceAccountName: iota-app
      
      containers:
      # Main application container
      - name: app
        image: iota-app:latest
        env:
        - name: VAULT_ADDR
          value: "http://127.0.0.1:8100"
        - name: VAULT_AGENT_MODE
          value: "true"
        - name: VAULT_MOUNT_PATH
          value: "transit"
        ports:
        - containerPort: 8080
      
      # Vault Agent sidecar
      - name: vault-agent
        image: hashicorp/vault:latest
        args:
        - "agent"
        - "-config=/vault/config/agent.hcl"
        env:
        - name: VAULT_ADDR
          value: "https://vault.company.com:8200"
        volumeMounts:
        - name: vault-config
          mountPath: /vault/config
        - name: vault-secrets
          mountPath: /vault/secrets
      
      volumes:
      - name: vault-config
        configMap:
          name: vault-agent-config
      - name: vault-secrets
        emptyDir:
          medium: Memory
```

### Vault Server Setup

1. **Enable Kubernetes Auth**:
```bash
vault auth enable kubernetes

vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token
```

2. **Create Role for App**:
```bash
vault write auth/kubernetes/role/iota-app \
    bound_service_account_names=iota-app \
    bound_service_account_namespaces=iota \
    policies=iota-transit \
    ttl=1h
```

3. **Create Transit Policy**:
```bash
vault policy write iota-transit - <<EOF
# Transit secrets engine operations
path "transit/keys/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "transit/sign/*" {
  capabilities = ["update"]
}

path "transit/verify/*" {
  capabilities = ["update"]
}
EOF
```

### Testing the Setup

```bash
# Deploy the application
kubectl apply -f deployment.yaml

# Check that both containers are running
kubectl get pods -n iota

# View logs
kubectl logs -n iota <pod-name> -c app
kubectl logs -n iota <pod-name> -c vault-agent

# Verify Vault Agent is working
kubectl exec -n iota <pod-name> -c vault-agent -- \
  cat /vault/secrets/token
```

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
docker-compose -f docker-compose.vault.yml up -d
cargo test --package vault-adapter -- --ignored
```

### Local Development Setup

```bash
# Start Vault development server
docker-compose -f docker-compose.vault.yml up -d

# Check status
docker-compose -f docker-compose.vault.yml ps

# View logs
docker-compose -f docker-compose.vault.yml logs -f vault

# Clean up
docker-compose -f docker-compose.vault.yml down
```

## Contributing

1. Follow the existing code style and patterns
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all examples compile and run
5. Test with both development and production Vault configurations

## License

Apache-2.0 - See [LICENSE](../../LICENSE) for details.