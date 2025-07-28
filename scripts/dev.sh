#!/bin/bash

# Development helper script for auth server

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Commands
case "${1:-help}" in
    "start")
        log_info "Starting development environment..."
        docker-compose up -d postgres redis
        log_success "Database and Redis started"
        log_info "Starting auth server..."
        CONFIG_PATH="./configs/config.dev.yaml" go run ./cmd/server
        ;;
    
    "docker")
        log_info "Starting full Docker environment..."
        docker-compose up --build
        ;;
        
    "docker-dev")
        log_info "Starting Docker with dev tools..."
        docker-compose --profile dev up --build
        ;;
    
    "stop")
        log_info "Stopping development environment..."
        docker-compose down
        log_success "Environment stopped"
        ;;
    
    "clean")
        log_warn "Cleaning up Docker environment (this will remove volumes)..."
        read -p "Are you sure? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down -v --remove-orphans
            docker system prune -f
            log_success "Cleanup complete"
        fi
        ;;
    
    "logs")
        docker-compose logs -f ${2:-auth-server}
        ;;
    
    "test")
        log_info "Running tests..."
        go test ./...
        log_success "Tests completed"
        ;;
    
    "build")
        log_info "Building application..."
        go build -o bin/server ./cmd/server
        log_success "Build completed: bin/server"
        ;;
    
    "deps")
        log_info "Installing dependencies..."
        go mod download
        go mod tidy
        log_success "Dependencies updated"
        ;;
    
    "help"|*)
        echo "Auth Server Development Helper"
        echo ""
        echo "Usage: ./scripts/dev.sh <command>"
        echo ""
        echo "Commands:"
        echo "  start      - Start databases and run server locally"
        echo "  docker     - Start full Docker environment"
        echo "  docker-dev - Start Docker with development tools"
        echo "  stop       - Stop all services"
        echo "  clean      - Clean up Docker environment (removes volumes)"
        echo "  logs [svc] - Show logs for service (default: auth-server)"
        echo "  test       - Run tests"
        echo "  build      - Build application binary"
        echo "  deps       - Update Go dependencies"
        echo "  help       - Show this help"
        echo ""
        echo "Development URLs:"
        echo "  Auth Server:     http://localhost:8080"
        echo "  Health Check:    http://localhost:8080/healthz"
        echo "  Adminer (DB):    http://localhost:8081 (with --profile dev)"
        echo "  Redis Commander: http://localhost:8082 (with --profile dev)"
        ;;
esac