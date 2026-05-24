#!/bin/bash
# DockSec Docker Runner Wrapper Script
# This script handles docker socket mounting and volume bindings for DockSec
# Usage: ./docker-runner.sh [OPTIONS]

set -e

# Configuration
DOCKSEC_IMAGE="${DOCKSEC_IMAGE:-owasp/docksec:latest}"
DOCKER_SOCKET="/var/run/docker.sock"
SCAN_DIR="${SCAN_DIR:-.}"
RESULTS_DIR="${RESULTS_DIR:-${SCAN_DIR}/results}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-}"

# Default DOCKERFILE_PATH to Dockerfile if it exists and not specified
if [ -z "$DOCKERFILE_PATH" ] && [ -f "$SCAN_DIR/Dockerfile" ]; then
    DOCKERFILE_PATH="Dockerfile"
fi

IMAGE_NAME="${IMAGE_NAME:-}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "${BLUE}=== DockSec Docker Runner ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

show_help() {
    cat << 'EOF'
DockSec Docker Runner - Run DockSec in a Docker container

USAGE:
    docker-runner.sh [OPTIONS]

ENVIRONMENT VARIABLES:
    DOCKSEC_IMAGE       Docker image to use (default: owasp/docksec:latest)
    SCAN_DIR            Directory containing Dockerfile (default: current directory)
    RESULTS_DIR         Output directory for reports (default: SCAN_DIR/results)
    DOCKERFILE_PATH     Path to Dockerfile relative to SCAN_DIR (default: Dockerfile)
    IMAGE_NAME          Docker image to scan (e.g., myapp:latest)
    VERBOSE             Enable verbose output (default: false)

EXAMPLES:
    # Scan a local Docker image only
    SCAN_DIR=. IMAGE_NAME=myapp:latest ./docker-runner.sh

    # Scan Dockerfile and Docker image
    SCAN_DIR=. DOCKERFILE_PATH=Dockerfile IMAGE_NAME=myapp:latest ./docker-runner.sh

    # Scan Dockerfile only (AI analysis)
    SCAN_DIR=. DOCKERFILE_PATH=Dockerfile ./docker-runner.sh --ai-only

    # Scan with custom results directory
    SCAN_DIR=. RESULTS_DIR=/tmp/docksec-results IMAGE_NAME=myapp:latest ./docker-runner.sh

    # Use environment variables for API keys
    export OPENAI_API_KEY="your-key"
    SCAN_DIR=. IMAGE_NAME=myapp:latest ./docker-runner.sh

NOTES:
    - Requires Docker daemon access (docker socket at /var/run/docker.sock)
    - Results are saved to RESULTS_DIR
    - API keys can be passed via environment variables

For more information, see docs/DOCKER_USAGE.md
EOF
}

# Check if Docker socket exists
check_docker_socket() {
    # Try to get socket from docker context (most reliable for Rancher/Desktop)
    if command -v docker >/dev/null 2>&1; then
        local context_socket=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || echo "")
        if [[ "$context_socket" == unix://* ]]; then
            DOCKER_SOCKET=${context_socket#unix://}
            if [ -S "$DOCKER_SOCKET" ]; then
                return 0
            fi
        fi
    fi

    # Fallback to standard locations
    local common_sockets=(
        "/var/run/docker.sock"
        "$HOME/.rd/docker.sock"
        "$HOME/.docker/run/docker.sock"
    )
    for socket in "${common_sockets[@]}"; do
        if [ -S "$socket" ]; then
            DOCKER_SOCKET="$socket"
            return 0
        fi
    done

    print_error "Docker socket not found. Please ensure Docker/Rancher is running."
    return 1
}

# Check Docker connection
check_docker_connection() {
    if ! docker ps > /dev/null 2>&1; then
        print_error "Cannot connect to Docker daemon on host"
        return 1
    fi
    return 0
}

# Prepare directories
prepare_directories() {
    if [ ! -d "$SCAN_DIR" ]; then
        print_error "SCAN_DIR does not exist: $SCAN_DIR"
        return 1
    fi
    
    # Create results directory if it doesn't exist
    mkdir -p "$RESULTS_DIR"
    print_success "Results directory: $RESULTS_DIR"
}

# Build docker run command
build_docker_command() {
    # On macOS/Rancher, the most reliable way is root + privileged + standard path
    local docker_cmd="docker run --rm --privileged --entrypoint docksec"
    
    # Add docker socket for image scanning
    # We mount the discovered socket to the standard location inside the container
    docker_cmd="$docker_cmd -v \"$DOCKER_SOCKET\":/var/run/docker.sock"
    
    # Add scan directory
    docker_cmd="$docker_cmd -v $(cd "$SCAN_DIR" && pwd):/scan"
    
    # Add results directory
    docker_cmd="$docker_cmd -v $(cd "$RESULTS_DIR" && pwd):/scan/results"
    docker_cmd="$docker_cmd -e DOCKSEC_RESULTS_DIR=/scan/results"
    
    # Pass through environment variables for API keys
    if [ -n "$OPENAI_API_KEY" ]; then
        docker_cmd="$docker_cmd -e OPENAI_API_KEY=$OPENAI_API_KEY"
    fi
    if [ -n "$ANTHROPIC_API_KEY" ]; then
        docker_cmd="$docker_cmd -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
    fi
    if [ -n "$GOOGLE_API_KEY" ]; then
        docker_cmd="$docker_cmd -e GOOGLE_API_KEY=$GOOGLE_API_KEY"
    fi

    # Auto-detect LLM_PROVIDER if not set but an API key is present
    if [ -z "$LLM_PROVIDER" ]; then
        if [ -n "$ANTHROPIC_API_KEY" ]; then
            LLM_PROVIDER="anthropic"
        elif [ -n "$GOOGLE_API_KEY" ]; then
            LLM_PROVIDER="google"
        elif [ -n "$OPENAI_API_KEY" ]; then
            LLM_PROVIDER="openai"
        fi
    fi

    if [ -n "$LLM_PROVIDER" ]; then
        docker_cmd="$docker_cmd -e LLM_PROVIDER=$LLM_PROVIDER"
    fi
    if [ -n "$LLM_MODEL" ]; then
        docker_cmd="$docker_cmd -e LLM_MODEL=$LLM_MODEL"
    fi
    
    # Pass through cache environment variable
    if [ -n "$DOCKSEC_USE_CACHE" ]; then
        docker_cmd="$docker_cmd -e DOCKSEC_USE_CACHE=$DOCKSEC_USE_CACHE"
    fi
    
    # Add image name
    docker_cmd="$docker_cmd $DOCKSEC_IMAGE"
    
    # Build docksec arguments
    local args=""
    
    if [ -n "$DOCKERFILE_PATH" ]; then
        args="$args /scan/$DOCKERFILE_PATH"
    fi
    
    if [ -n "$IMAGE_NAME" ]; then
        args="$args -i $IMAGE_NAME"
    fi
    
    # Output directory (always use /scan/results inside container)
    args="$args -o /scan/results/security_report"
    
    # Add any additional arguments passed to this script
    if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
        for arg in "${EXTRA_ARGS[@]}"; do
            args="$args $arg"
        done
    fi
    
    docker_cmd="$docker_cmd $args"
    
    echo "$docker_cmd"
}

# Main execution
main() {
    # Parse additional arguments for docksec
    EXTRA_ARGS=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            *)
                EXTRA_ARGS+=("$1")
                shift
                ;;
        esac
    done
    
    print_header
    echo ""
    
    # Validate environment
    print_info "Validating Docker environment..."
    if ! check_docker_socket; then
        return 1
    fi
    print_success "Docker socket found"
    
    if ! check_docker_connection; then
        return 1
    fi
    print_success "Docker connection OK"
    
    # Prepare
    print_info "Preparing directories..."
    if ! prepare_directories; then
        return 1
    fi
    
    # Build command
    print_info "Building docker command..."
    local cmd=$(build_docker_command)
    
    if [ "$VERBOSE" = "true" ]; then
        print_info "Docker command:"
        echo "$cmd"
        echo ""
        print_info "Socket info:"
        ls -la "$DOCKER_SOCKET"
        echo ""
    fi
    
    # Pull image if needed
    print_info "Ensuring image is available: $DOCKSEC_IMAGE"
    if ! docker image inspect "$DOCKSEC_IMAGE" > /dev/null 2>&1; then
        print_info "Image not found locally, pulling..."
        docker pull "$DOCKSEC_IMAGE" > /dev/null 2>&1 || {
            print_error "Failed to pull image: $DOCKSEC_IMAGE"
            return 1
        }
    fi
    print_success "Image ready"
    
    echo ""
    print_info "Starting DockSec scan..."
    echo "---"
    
    # Run docker command
    eval "$cmd"
    local exit_code=$?
    
    echo "---"
    if [ $exit_code -eq 0 ]; then
        echo ""
        print_success "Scan completed successfully"
        print_info "Results saved to: $RESULTS_DIR"
        return 0
    else
        echo ""
        print_error "Scan failed with exit code $exit_code"
        return $exit_code
    fi
}

# Run main function
main "$@"
