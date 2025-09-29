#!/bin/bash
# Copyright 2020-2024 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

#
# HashiCorp Vault Development Environment Setup
#
# This script starts a development Vault server using Docker with:
# - Transit secrets engine enabled
# - Development mode (data is not persisted)
# - Root token for easy testing
# - Proper logging configuration
#
# Usage:
#   ./scripts/vault-dev.sh [start|stop|status|logs|clean]
#
# Environment variables after startup:
#   export VAULT_ADDR="http://localhost:8200"
#   export VAULT_TOKEN="dev-token"
#   export VAULT_MOUNT_PATH="transit"
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VAULT_VERSION="1.15"
CONTAINER_NAME="iota-vault-dev"
VAULT_PORT="8200"
VAULT_ADDR="http://localhost:${VAULT_PORT}"
VAULT_TOKEN="dev-token"
MOUNT_PATH="transit"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                   🔐 IOTA Vault Dev Environment              ║"
    echo "║                    HashiCorp Vault ${VAULT_VERSION}                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is required but not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
}

check_container_exists() {
    docker ps -a --format "table {{.Names}}" | grep -q "^${CONTAINER_NAME}$"
}

check_container_running() {
    docker ps --format "table {{.Names}}" | grep -q "^${CONTAINER_NAME}$"
}

wait_for_vault() {
    print_step "Waiting for Vault to be ready..."
    
    max_attempts=30
    attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
            print_success "Vault is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done
    
    print_error "Vault failed to start within ${max_attempts} seconds"
    return 1
}

enable_transit_engine() {
    print_step "Enabling Transit secrets engine..."
    
    # Check if transit engine is already enabled
    if docker exec ${CONTAINER_NAME} vault auth -method=token token=${VAULT_TOKEN} > /dev/null 2>&1 && \
       docker exec ${CONTAINER_NAME} vault secrets list | grep -q "${MOUNT_PATH}/"; then
        print_step "Transit engine already enabled at ${MOUNT_PATH}/"
        return 0
    fi
    
    # Enable transit engine
    if docker exec ${CONTAINER_NAME} sh -c "
        export VAULT_TOKEN=${VAULT_TOKEN} && \
        vault secrets enable -path=${MOUNT_PATH} transit
    " > /dev/null 2>&1; then
        print_success "Transit secrets engine enabled at ${MOUNT_PATH}/"
    else
        print_error "Failed to enable Transit secrets engine"
        return 1
    fi
}

start_vault() {
    print_header
    check_docker
    
    if check_container_running; then
        print_step "Vault container is already running"
        show_connection_info
        return 0
    fi
    
    if check_container_exists; then
        print_step "Starting existing Vault container..."
        docker start ${CONTAINER_NAME} > /dev/null
    else
        print_step "Creating new Vault development container..."
        docker run -d \
            --name ${CONTAINER_NAME} \
            --cap-add=IPC_LOCK \
            -p ${VAULT_PORT}:8200 \
            -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" \
            -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
            vault:${VAULT_VERSION} > /dev/null
    fi
    
    if wait_for_vault; then
        enable_transit_engine
        show_connection_info
        show_usage_examples
    else
        print_error "Failed to start Vault properly"
        docker logs ${CONTAINER_NAME}
        exit 1
    fi
}

stop_vault() {
    print_header
    
    if check_container_running; then
        print_step "Stopping Vault container..."
        docker stop ${CONTAINER_NAME} > /dev/null
        print_success "Vault container stopped"
    else
        print_step "Vault container is not running"
    fi
}

show_status() {
    print_header
    
    if check_container_running; then
        print_success "Vault container is running"
        
        echo ""
        echo "Container Details:"
        docker ps --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        echo ""
        echo "Vault Status:"
        if curl -s "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
            docker exec ${CONTAINER_NAME} sh -c "
                export VAULT_TOKEN=${VAULT_TOKEN} && \
                vault status
            " 2>/dev/null || echo "Failed to get vault status"
        else
            print_error "Vault API is not accessible"
        fi
        
        show_connection_info
    elif check_container_exists; then
        print_step "Vault container exists but is not running"
        echo ""
        docker ps -a --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    else
        print_step "Vault container does not exist"
    fi
}

show_logs() {
    if check_container_exists; then
        print_step "Showing Vault container logs..."
        echo ""
        docker logs -f ${CONTAINER_NAME}
    else
        print_error "Vault container does not exist"
        exit 1
    fi
}

clean_vault() {
    print_header
    
    if check_container_exists; then
        print_step "Removing Vault container and data..."
        docker rm -f ${CONTAINER_NAME} > /dev/null 2>&1 || true
        print_success "Vault container removed"
    else
        print_step "No Vault container to clean"
    fi
}

show_connection_info() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    🔗 Connection Information                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Environment variables:"
    echo -e "  ${YELLOW}export VAULT_ADDR=\"${VAULT_ADDR}\"${NC}"
    echo -e "  ${YELLOW}export VAULT_TOKEN=\"${VAULT_TOKEN}\"${NC}"
    echo -e "  ${YELLOW}export VAULT_MOUNT_PATH=\"${MOUNT_PATH}\"${NC}"
    echo ""
    echo "Vault UI: ${VAULT_ADDR}/ui"
    echo "API Health: ${VAULT_ADDR}/v1/sys/health"
}

show_usage_examples() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                      📚 Usage Examples                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Run Vault adapter examples:"
    echo -e "  ${BLUE}cargo run --package vault-adapter --example basic_usage${NC}"
    echo -e "  ${BLUE}cargo run --package vault-adapter --example signing_demo${NC}"
    echo ""
    echo "Test with curl:"
    echo -e "  ${BLUE}curl -H \"X-Vault-Token: ${VAULT_TOKEN}\" ${VAULT_ADDR}/v1/sys/health${NC}"
    echo ""
    echo "Run adapter tests:"
    echo -e "  ${BLUE}cargo test --package vault-adapter${NC}"
}

show_help() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start     Start Vault development server (default)"
    echo "  stop      Stop Vault development server"
    echo "  status    Show Vault server status"
    echo "  logs      Show Vault server logs (follow mode)"
    echo "  clean     Remove Vault container and data"
    echo "  help      Show this help message"
    echo ""
    echo "Environment:"
    echo "  VAULT_ADDR=http://localhost:8200"
    echo "  VAULT_TOKEN=dev-token"
    echo "  VAULT_MOUNT_PATH=transit"
}

# Main command handling
case "${1:-start}" in
    start)
        start_vault
        ;;
    stop)
        stop_vault
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    clean)
        clean_vault
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac