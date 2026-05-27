#!/bin/bash
# AgentSniff One-Liner Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/scripts/install.sh | bash

set -e

VERSION="latest"
INSTALL_DIR="${AGENTSNIFF_INSTALL_DIR:-$HOME/.agentsniff}"
BIN_DIR="$INSTALL_DIR/bin"
GITHUB_REPO="ThirdKeyAI/agentsniff"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   AgentSniff Installation Script      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo

detect_platform() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch
    arch=$(uname -m)

    case "$os" in
        linux*)  OS="linux" ;;
        darwin*) OS="darwin" ;;
        mingw*|msys*|cygwin*)
            echo -e "${RED}✗ Windows is not supported by this installer.${NC}"
            echo -e "${YELLOW}  Download the .zip archive from the GitHub release page,${NC}"
            echo -e "${YELLOW}  or install via 'cargo install agentsniff'.${NC}"
            exit 1
            ;;
        *) echo -e "${RED}✗ Unsupported OS: $os${NC}"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64)   ARCH="x86_64" ;;
        aarch64|arm64)  ARCH="aarch64" ;;
        *) echo -e "${RED}✗ Unsupported architecture: $arch${NC}"; exit 1 ;;
    esac

    PLATFORM="${OS}-${ARCH}"

    case "${OS}-${ARCH}" in
        linux-x86_64)   RUST_TARGET="x86_64-unknown-linux-gnu" ;;
        linux-aarch64)  RUST_TARGET="aarch64-unknown-linux-gnu" ;;
        darwin-aarch64) RUST_TARGET="aarch64-apple-darwin" ;;
        darwin-x86_64)  RUST_TARGET="x86_64-apple-darwin" ;;
        *)
            echo -e "${RED}✗ No pre-built binary for ${OS}-${ARCH}${NC}"
            echo -e "${YELLOW}  Install from source: cargo install agentsniff${NC}"
            exit 1
            ;;
    esac

    echo -e "• Detected platform: ${GREEN}${PLATFORM}${NC}"
}

check_prerequisites() {
    echo "• Checking prerequisites..."

    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        echo -e "${RED}✗ Neither curl nor wget found. Please install one of them.${NC}"
        exit 1
    fi

    if ! command -v tar >/dev/null 2>&1; then
        echo -e "${RED}✗ tar not found. Please install tar.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Prerequisites met${NC}"
}

install_binary() {
    echo "• Downloading AgentSniff ${VERSION}..."

    mkdir -p "$BIN_DIR"

    local base_url
    if [ "$VERSION" = "latest" ]; then
        base_url="https://github.com/${GITHUB_REPO}/releases/latest/download"
    else
        base_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    fi

    # The release-binaries workflow names archives "agentsniff-<tag>-<target>.tar.gz".
    # When VERSION=latest we can't know the tag up front — fall back to the
    # `latest/download` redirect path with a wildcard-resolving lookup.
    local archive
    if [ "$VERSION" = "latest" ]; then
        # Probe latest release tag via the GitHub API redirect.
        local tag
        tag=$(curl -fsSLI "https://github.com/${GITHUB_REPO}/releases/latest" \
            | awk -F'/' '/^location:/ { gsub("\r",""); print $NF }' | tail -1)
        if [ -z "$tag" ]; then
            echo -e "${RED}✗ Failed to resolve latest release tag.${NC}"
            echo -e "${YELLOW}  Try cargo install agentsniff instead.${NC}"
            exit 1
        fi
        archive="agentsniff-${tag}-${RUST_TARGET}.tar.gz"
    else
        archive="agentsniff-${VERSION}-${RUST_TARGET}.tar.gz"
    fi

    local download_url="${base_url}/${archive}"
    local checksums_url="${base_url}/checksums.txt"

    local temp_dir
    temp_dir=$(mktemp -d)
    local temp_file="${temp_dir}/${archive}"
    local temp_checksums="${temp_dir}/checksums.txt"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$temp_file" || {
            echo -e "${RED}✗ Failed to download AgentSniff${NC}"
            echo -e "${YELLOW}  URL: ${download_url}${NC}"
            echo -e "${YELLOW}  Try: cargo install agentsniff${NC}"
            rm -rf "$temp_dir"
            exit 1
        }
        curl -fsSL "$checksums_url" -o "$temp_checksums" 2>/dev/null || true
    else
        wget -q "$download_url" -O "$temp_file" || {
            echo -e "${RED}✗ Failed to download AgentSniff${NC}"
            rm -rf "$temp_dir"
            exit 1
        }
        wget -q "$checksums_url" -O "$temp_checksums" 2>/dev/null || true
    fi

    if [ -s "$temp_checksums" ] && command -v sha256sum >/dev/null 2>&1; then
        echo "• Verifying checksum..."
        (cd "$temp_dir" && grep "$archive" checksums.txt | sha256sum --check --quiet) && {
            echo -e "${GREEN}✓ Checksum verified${NC}"
        } || {
            echo -e "${RED}✗ Checksum verification failed!${NC}"
            rm -rf "$temp_dir"
            exit 1
        }
    fi

    tar -xzf "$temp_file" -C "$BIN_DIR"
    rm -rf "$temp_dir"

    chmod +x "$BIN_DIR/agentsniff"
    echo -e "${GREEN}✓ Binary installed to ${BIN_DIR}/agentsniff${NC}"
}

update_path() {
    echo "• Updating PATH..."

    local shell_rc=""
    if [ -n "$BASH_VERSION" ]; then
        shell_rc="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        shell_rc="$HOME/.zshrc"
    else
        shell_rc="$HOME/.profile"
    fi

    if ! echo "$PATH" | grep -q "$BIN_DIR"; then
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$shell_rc"
        echo -e "${GREEN}✓ Added ${BIN_DIR} to PATH in ${shell_rc}${NC}"
        echo -e "${YELLOW}  Run: source ${shell_rc}${NC}"
    else
        echo -e "${GREEN}✓ PATH already contains ${BIN_DIR}${NC}"
    fi

    export PATH="$PATH:$BIN_DIR"
}

post_install() {
    echo
    echo -e "${GREEN}✅ Installation complete!${NC}"
    echo
    echo "📝 Next steps:"
    echo "  1. Reload your shell or run: source ~/.bashrc (or ~/.zshrc)"
    echo "  2. Verify installation: agentsniff --version"
    echo "  3. Run a scan:           agentsniff scan 192.168.1.0/24"
    echo "  4. Start the dashboard:  agentsniff serve --port 9090"
    echo
    echo "📚 Documentation: https://docs.agentsniff.org"
    echo "🐛 Issues:         https://github.com/${GITHUB_REPO}/issues"
    echo
}

main() {
    detect_platform
    check_prerequisites
    install_binary
    update_path
    post_install
}

main
