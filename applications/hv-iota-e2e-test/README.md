# IOTA Secret Storage Transaction API

**Simplified API per eseguire transazioni IOTA con HashiCorp Vault in ambiente containerizzato K8s-like.**

## Solo 2 Endpoint

1. **POST /execute-transaction** - Esegue l'intero workflow IOTA Vault Demo e ritorna il link della transazione
2. **GET /keys** - Lista delle chiavi Vault con i loro indirizzi IOTA

## Quick Start

### 1. Avvia l'ambiente completo

```bash
# Dalla root del progetto
docker-compose up -d

# Verifica che tutto funzioni
curl http://localhost:3000/health
```

### 2. Esegui una transazione IOTA

```bash
# Esegue l'intero workflow: genera chiave → faucet → transazione → link explorer
curl -X POST http://localhost:3000/execute-transaction \
  -H "Content-Type: application/json" \
  -d '{
    "target_address": "0x1f9699f7b7baee05b2a6eea4eb41bb923fb64732069a1bf010506cd3d2d9ab26",
    "amount": 5000000,
    "description": "Test transaction from API"
  }'
```

**⚠️ La chiamata può richiedere 30-60 secondi** perché esegue tutto il workflow:
1. Genera nuova chiave Vault con timestamp
2. Deriva indirizzo IOTA dalla chiave
3. Richiede fondi al faucet testnet
4. Aspetta 5 secondi per il processing
5. Controlla il balance
6. Prepara e invia la transazione
7. Ritorna il link dell'explorer

### 3. Lista le chiavi

```bash
# Mostra tutte le chiavi Vault con i loro indirizzi IOTA
curl http://localhost:3000/keys
```

## API Endpoints

### 🚀 Endpoint Principali

#### POST /execute-transaction
Esegue l'intero script `iota_vault_demo.rs` via API.

**Request:**
```json
{
  "target_address": "0x...",  // Opzionale, default predefinito
  "amount": 5000000,          // Opzionale, default 0.005 IOTA in MIST
  "description": "My tx"      // Opzionale
}
```

**Response di successo:**
```json
{
  "success": true,
  "message": "Transaction executed successfully",
  "transaction_digest": "0x123abc...",
  "explorer_url": "https://explorer.iota.org/txblock/0x123abc...?network=testnet",
  "key_id": "vault-demo-1699123456789",
  "from_address": "0xabc123...",
  "to_address": "0x1f9699...",
  "amount_mist": 5000000,
  "amount_iota": 0.005,
  "executed_at": "2024-01-01T12:00:00Z"
}
```

#### GET /keys
Lista delle chiavi Vault con indirizzi IOTA.

**Response:**
```json
{
  "keys": [
    {
      "key_id": "vault-demo-1699123456789",
      "iota_address": "0xabc123...",
      "created_at": "2024-01-01T12:00:00Z"
    }
  ],
  "total": 1
}
```

### 🔍 Health Check
- `GET /health` - Stato dell'API e connessione Vault

## Configuration

### Environment Variables

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=3000

# Storage Backend
STORAGE_BACKEND=vault  # vault | aws

# Vault Configuration (if using Vault)
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=dev-token
VAULT_MOUNT_PATH=transit

# AWS Configuration (if using AWS)
AWS_REGION=eu-west-1
AWS_PROFILE=your-profile
KMS_KEY_ID=optional-key-id

# IOTA Configuration
IOTA_NETWORK=testnet
ENVIRONMENT=development

# Logging
RUST_LOG=info,transaction_api=debug
```

## Development

### Local Development

```bash
# Install dependencies
cargo build --package transaction-api

# Run with Vault backend
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=dev-token \
cargo run --package transaction-api
```

### Building Docker Image

```bash
# Build image
docker build -f applications/transaction-api/Dockerfile -t iota-transaction-api .

# Run container
docker run -p 3000:3000 \
  -e VAULT_ADDR=http://vault:8200 \
  -e VAULT_TOKEN=dev-token \
  iota-transaction-api
```

## Kubernetes Deployment

The service is designed for K8s deployment with the following considerations:

### Service Discovery
- Uses internal DNS for Vault connectivity
- Health checks for readiness and liveness probes
- Graceful shutdown handling

### Security
- Non-root container execution
- Secret management through K8s secrets
- Network policies for service isolation

### Example K8s Manifests

```yaml
# Secret for Vault token
apiVersion: v1
kind: Secret
metadata:
  name: vault-token
type: Opaque
data:
  token: ZGV2LXRva2Vu  # base64 encoded "dev-token"

---
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: transaction-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: transaction-api
  template:
    metadata:
      labels:
        app: transaction-api
    spec:
      containers:
      - name: transaction-api
        image: iota-transaction-api:latest
        ports:
        - containerPort: 3000
        env:
        - name: VAULT_ADDR
          value: "http://vault:8200"
        - name: VAULT_TOKEN
          valueFrom:
            secretKeyRef:
              name: vault-token
              key: token
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
```

## Security Considerations

### Production Deployment
- Use proper Vault authentication (not dev tokens)
- Implement TLS termination
- Configure network segmentation
- Set up proper logging and monitoring
- Use secrets management for sensitive configuration

### Vault Security
- Configure proper Vault policies
- Use least-privilege access patterns
- Enable audit logging
- Implement proper key rotation

## Troubleshooting

### Common Issues

1. **Vault Connection Failed**
   ```bash
   # Check Vault status
   curl http://localhost:8200/v1/sys/health

   # Verify transit engine
   docker-compose logs vault-init
   ```

2. **Key Creation Failed**
   ```bash
   # Check Vault policies
   VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-token \
   vault auth -method=token

   # Test transit operations
   vault write transit/keys/test-key type=ecdsa-p256
   ```

3. **Container Won't Start**
   ```bash
   # Check container logs
   docker-compose logs transaction-api

   # Verify environment variables
   docker-compose exec transaction-api env
   ```

## Contributing

1. Follow existing code patterns
2. Add tests for new functionality
3. Update documentation
4. Ensure Docker builds succeed
5. Verify K8s compatibility