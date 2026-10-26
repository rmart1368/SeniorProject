#!/usr/bin/env bash
# Install Ubuntu/Debian prerequisites for building and installing ChompEDR.
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: bash scripts/install-dependencies-linux.sh"
    echo "Installs build-essential, curl, ca-certificates, Python 3, D-Bus and stable Rust if missing."
    echo "Run as a regular user. Uses sudo for apt; does not build ChompEDR or start services."
    exit 0
fi
if (( $# != 0 )); then
    echo "Unexpected arguments; use --help." >&2
    exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This dependency installer requires Ubuntu/Debian Linux." >&2
    exit 1
fi
if (( EUID == 0 )); then
    echo "Run without sudo. The script uses sudo only for system packages." >&2
    exit 1
fi
if [[ ! -r /etc/os-release ]]; then
    echo "Cannot identify the Linux distribution." >&2
    exit 1
fi
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*) ;;
    *) echo "Supported distributions: Ubuntu/Debian and their derivatives." >&2; exit 1 ;;
esac
if ! command -v sudo >/dev/null || ! command -v apt-get >/dev/null; then
    echo "sudo and apt-get are required." >&2
    exit 1
fi

echo "Installing build tools, HTTPS certificates, curl Python 3 and D-Bus..."
sudo apt-get update
sudo apt-get install -y build-essential curl ca-certificates python3 dbus

# Locate an existing user Rust installation even in a newly opened shell.
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if ! command -v cargo >/dev/null || ! command -v rustc >/dev/null; then
    if command -v rustup >/dev/null; then
        rustup toolchain install stable --profile minimal
        rustup default stable
    else
        installer="$(mktemp)"
        trap 'rm -f -- "$installer"' EXIT
        curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
            https://sh.rustup.rs --output "$installer"
        sh "$installer" -y --profile minimal --default-toolchain stable --no-modify-path
    fi
fi

echo
echo "Checking prerequisites..."
cc --version >/dev/null
python3 --version
cargo --version
rustc --version
echo
echo "Dependencies are ready. From the repository folder, install with:"
echo "  python3 scripts/install-linux.py"
echo "If cargo is unavailable in your terminal, first run:"
echo '  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"'
echo "Cargo downloads the project's Rust dependencies during the build."
