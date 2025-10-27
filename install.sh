#!/bin/bash
set -e

# YKVC Download Script
# Usage: curl -sSL https://raw.githubusercontent.com/dzatona/ykvc/main/install.sh | bash

REPO="dzatona/ykvc"
BINARY_NAME="ykvc"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        linux)
            if [ "$arch" != "x86_64" ]; then
                log_error "Unsupported architecture: $arch (only x86_64 is supported on Linux)"
                exit 1
            fi
            PLATFORM="x86_64-unknown-linux-gnu"
            ;;
        darwin)
            PLATFORM="universal-apple-darwin"
            ;;
        *)
            log_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
}

# Get latest version from GitHub
get_latest_version() {
    log_info "Fetching latest version..."

    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        log_error "Failed to get latest version"
        exit 1
    fi

    log_info "Latest version: v${VERSION}"
}

# Download and extract binary
download_binary() {
    local filename="ykvc-${VERSION}-${PLATFORM}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/v${VERSION}/${filename}"
    local extract_dir="ykvc-${VERSION}-${PLATFORM}"

    log_info "Downloading from: $url"

    if command -v curl >/dev/null 2>&1; then
        curl -sSL -o "${filename}" "$url"
    else
        wget -qO "${filename}" "$url"
    fi

    log_info "Extracting archive..."
    mkdir -p "${extract_dir}"
    tar -xzf "${filename}" -C "${extract_dir}"

    log_info "Cleaning up archive..."
    rm -f "${filename}"

    log_info "Binary extracted to: ./${extract_dir}/${BINARY_NAME}"
}

# Main flow
main() {
    log_info "Starting YKVC download..."

    detect_platform
    log_info "Detected platform: $PLATFORM"

    get_latest_version
    download_binary

    echo ""
    log_info "Download complete! "
    echo ""
    echo "To use ykvc:"
    echo "  cd ykvc-${VERSION}-${PLATFORM}"
    echo "  ./ykvc --help"
    echo ""
    echo "Next steps:"
    echo "  1. Run './ykvc info' to check YubiKey"
    echo "  2. Program slot 2: './ykvc slot2 program'"
    echo "  3. Generate keyfile: './ykvc generate'"
    echo ""
    echo "For more information, visit: https://github.com/${REPO}"
}

main
