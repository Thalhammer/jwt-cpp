#!/usr/bin/env bash

install_init() {
    INSTALL_VERSION="${1:-}"
    if [[ "$INSTALL_VERSION" == "-h" || "$INSTALL_VERSION" == "--help" ]]; then
        echo "Usage: $0 VERSION [--prefix PATH] [--jobs N]"
        exit 0
    fi
    if [[ -z "$INSTALL_VERSION" ]]; then
        echo "Usage: $0 VERSION [--prefix PATH] [--jobs N]" >&2
        exit 1
    fi
    shift

    INSTALL_PREFIX="${JWT_CPP_INSTALL_PREFIX:-$HOME/.local}"
    INSTALL_JOBS="${JWT_CPP_INSTALL_JOBS:-2}"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefix)
                [[ $# -ge 2 && -n "$2" ]] || { echo "Missing path after --prefix" >&2; return 2; }
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            --jobs)
                [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || { echo "--jobs must be a positive integer" >&2; return 2; }
                INSTALL_JOBS="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1" >&2
                return 2
                ;;
        esac
    done
    case "$INSTALL_PREFIX" in
        *$'\n'*) echo "Install prefix cannot contain a newline" >&2; return 2 ;;
    esac

    mkdir -p "$INSTALL_PREFIX"
    INSTALL_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jwt-cpp-install.XXXXXX")"
    trap 'rm -rf "$INSTALL_WORK_DIR"' EXIT
}

install_require() {
    local command
    for command in "$@"; do
        if ! command -v "$command" >/dev/null 2>&1; then
            echo "Required command not found: $command" >&2
            return 1
        fi
    done
}

install_download_extract() {
    local url="$1"
    local archive="$2"
    install_require curl tar
    curl --fail --location --retry 3 --silent --show-error "$url" --output "$INSTALL_WORK_DIR/$archive"
    tar -xf "$INSTALL_WORK_DIR/$archive" -C "$INSTALL_WORK_DIR"
}

install_prepend_env() {
    local name="$1"
    local value="$2"
    local current="${!name:-}"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        if [[ ":$current:" != *":$value:"* ]]; then
            printf '%s=%s\n' "$name" "$value${current:+:$current}" >> "$GITHUB_ENV"
        fi
    fi
}

install_set_env() {
    local name="$1"
    local value="$2"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        printf '%s=%s\n' "$name" "$value" >> "$GITHUB_ENV"
    fi
}

install_publish_environment() {
    local extra_variable="${1:-}"
    local pkgconfig_path="$INSTALL_PREFIX/lib/pkgconfig:$INSTALL_PREFIX/lib64/pkgconfig"
    local library_path="$INSTALL_PREFIX/lib:$INSTALL_PREFIX/lib64"
    install_prepend_env CMAKE_PREFIX_PATH "$INSTALL_PREFIX"
    install_prepend_env PKG_CONFIG_PATH "$pkgconfig_path"
    install_prepend_env LD_LIBRARY_PATH "$library_path"
    install_prepend_env DYLD_LIBRARY_PATH "$library_path"
    if [[ -n "$extra_variable" ]]; then
        install_set_env "$extra_variable" "$INSTALL_PREFIX"
    fi
}
