# Environment Variables Reference

Complete reference for all environment variables used in IOTA Secret Storage.

## AWS KMS Configuration

### Authentication

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_PROFILE` | No* | - | AWS profile name from `~/.aws/config` (recommended) |
| `AWS_ACCESS_KEY_ID` | No* | - | AWS access key ID for direct authentication |
| `AWS_SECRET_ACCESS_KEY` | No* | - | AWS secret access key for direct authentication |
| `AWS_SESSION_TOKEN` | No | - | AWS session token for temporary credentials |
| `AWS_REGION` | **Yes** | - | AWS region (e.g., `eu-west-1`, `us-east-1`) |

\* Either `AWS_PROFILE` or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` must be provided

### Optional Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KMS_KEY_ID` | No | - | Specific KMS key ID or alias to use |
| `AWS_ENDPOINT_URL` | No | - | Custom endpoint URL (e.g., for LocalStack: `http://localhost:4566`) |

### Examples

**Profile-based authentication (Recommended):**
```bash
export AWS_PROFILE=your-profile-name
export AWS_REGION=eu-west-1
```

**Direct credentials:**
```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=eu-west-1
```

**LocalStack (development):**
```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_REGION=us-east-1
```


## General Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RUST_LOG` | No | `info` | Log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `ENVIRONMENT` | No | `development` | Environment type (`development`, `testing`, `production`) |

### Examples

**Debug logging:**
```bash
export RUST_LOG=debug
```

**Production with minimal logging:**
```bash
export RUST_LOG=warn
export ENVIRONMENT=production
```

## IOTA Network Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IOTA_NETWORK` | No | `testnet` | IOTA network to use (`mainnet`, `testnet`) |

### Example

```bash
export IOTA_NETWORK=testnet
```

## Complete Configuration Examples

### AWS KMS Development

```bash
# AWS configuration
export AWS_PROFILE=iota-dev
export AWS_REGION=eu-west-1

# General settings
export RUST_LOG=debug
export ENVIRONMENT=development
export IOTA_NETWORK=testnet

# Run example
cargo run --package storage-factory --example iota_kms_demo
```


## Environment File (.env)

All variables can be stored in a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env

# Edit with your values
vim .env
```

The application will automatically load variables from `.env` if present.

## Security Best Practices

### Development
✅ Use AWS profiles instead of direct credentials  
✅ Store credentials in `.env` (excluded from git)  
✅ Enable debug logging for troubleshooting  

### Production
✅ Use AWS IAM roles or instance profiles  
✅ Never commit credentials to version control  
✅ Use minimal log levels (info/warn)  
✅ Rotate tokens regularly  

## Troubleshooting

### AWS Authentication Issues

**Error:** `CredentialsError: Unable to locate credentials`

**Solution:** Ensure one of these is set:
```bash
export AWS_PROFILE=your-profile-name
# OR
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
```


## Related Documentation

- [README.md](../README.md) - Main project documentation
- [AWS_INTEGRATION.md](../AWS_INTEGRATION.md) - AWS KMS setup guide
- [.env.example](../.env.example) - Complete environment file template
