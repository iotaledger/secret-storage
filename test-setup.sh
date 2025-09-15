#!/bin/bash

# =================================================================
# IOTA Secret Storage - AWS Setup Test Script
# =================================================================

set -e

echo "🔧 IOTA Secret Storage AWS Setup Test"
echo "======================================"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "📋 Creating .env file from .env.example..."
    cp .env.example .env
    echo "✅ .env file created"
else
    echo "✅ .env file already exists"
fi

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install it first:"
    echo "   curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
    echo "   unzip awscliv2.zip"
    echo "   sudo ./aws/install"
    exit 1
fi

echo "✅ AWS CLI found: $(aws --version)"

# Check AWS configuration files
if [ ! -f "~/.aws/config" ] && [ ! -f "$HOME/.aws/config" ]; then
    echo "📋 AWS config file not found. Creating example..."
    mkdir -p ~/.aws
    cat > ~/.aws/config << EOF
[default]
region = eu-west-1

[profile developer]
role_arn = arn:aws:iam::304431203043:role/DeveloperFullAccessRole
source_profile = default
region = eu-west-1
EOF
    echo "✅ Created ~/.aws/config with developer profile"
    echo "⚠️  Remember to add your credentials to ~/.aws/credentials:"
    echo "   [default]"
    echo "   aws_access_key_id = YOUR_ACCESS_KEY"
    echo "   aws_secret_access_key = YOUR_SECRET_KEY"
else
    echo "✅ AWS config file exists"
fi

# Test AWS profile (if credentials are configured)
echo ""
echo "🔍 Testing AWS Configuration..."
if aws sts get-caller-identity --profile developer --region eu-west-1 &>/dev/null; then
    echo "✅ AWS profile 'developer' works!"
    echo "👤 Current identity:"
    aws sts get-caller-identity --profile developer --region eu-west-1 --output table
else
    echo "⚠️  AWS profile test failed. This is expected if credentials aren't configured yet."
    echo "   Configure credentials in ~/.aws/credentials:"
    echo "   [default]"
    echo "   aws_access_key_id = YOUR_ACCESS_KEY"
    echo "   aws_secret_access_key = YOUR_SECRET_KEY"
fi

# Test Rust compilation
echo ""
echo "🦀 Testing Rust Compilation..."
if cargo check --package aws-kms-adapter &>/dev/null; then
    echo "✅ AWS KMS adapter compiles successfully"
else
    echo "❌ Compilation failed. Check your Rust installation."
    exit 1
fi

if cargo check --package storage-factory &>/dev/null; then
    echo "✅ Storage factory compiles successfully"  
else
    echo "❌ Storage factory compilation failed"
    exit 1
fi

# Test examples (only compilation, not execution)
echo ""
echo "📦 Testing Examples Compilation..."

examples=(
    "aws-kms-adapter:key_storage_test"
    "aws-kms-adapter:profile_usage"
    "aws-kms-adapter:enterprise_service"
    "storage-factory:auto_detect_test"
    "storage-factory:iota_transaction_signing"
)

for example in "${examples[@]}"; do
    package=$(echo $example | cut -d: -f1)
    name=$(echo $example | cut -d: -f2)
    
    if cargo check --package $package --example $name &>/dev/null; then
        echo "✅ Example $name compiles"
    else
        echo "❌ Example $name compilation failed"
    fi
done

echo ""
echo "🎉 Setup Test Completed!"
echo ""
echo "📚 Next Steps:"
echo "1. Configure AWS credentials in ~/.aws/credentials"
echo "2. Test AWS access: aws sts get-caller-identity --profile developer"
echo "3. Run IOTA examples:"
echo "   cargo run --package storage-factory --example iota_transaction_signing"
echo "   cargo run --package aws-kms-adapter --example profile_usage"
echo ""
echo "📖 See README-AWS.md for detailed setup instructions"