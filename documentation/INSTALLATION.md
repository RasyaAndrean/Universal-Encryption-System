# Installation and Setup Guide

## System Requirements

### Minimum Requirements:
- **Operating System**: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 18.04+, CentOS 7+)
- **Processor**: x86_64 architecture
- **Memory**: 2 GB RAM minimum (4 GB recommended)
- **Storage**: 100 MB available disk space
- **Rust**: Version 1.70 or later

### Recommended Specifications:
- **Memory**: 4 GB RAM or more
- **Storage**: 1 GB available disk space for development
- **Processor**: Multi-core CPU for better performance

## Installing Rust

### Windows:
1. Download the Rust installer from [rust-lang.org](https://www.rust-lang.org/tools/install)
2. Run `rustup-init.exe` and follow the prompts
3. Restart your command prompt
4. Verify installation:
   ```cmd
   rustc --version
   cargo --version
   ```

### macOS:
```bash
# Using Homebrew
brew install rust

# Or using rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Linux:
```bash
# Using rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Or using package manager
# Ubuntu/Debian
sudo apt update
sudo apt install rustc cargo

# CentOS/RHEL
sudo yum install rust cargo
```

## Building from Source

### 1. Clone the Repository
```bash
git clone https://github.com/RasyaAndrean/file-encryptor.git
cd file-encryptor
```

### 2. Build the Project
```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Build with all features
cargo build --release --all-features
```

### 3. Run Tests
```bash
# Run all tests
cargo test

# Run specific test suite
cargo test integration_tests

# Run with verbose output
cargo test -- --nocapture

# Run documentation tests
cargo test --doc
```

### 4. Install System-wide (Optional)
```bash
# Install to ~/.cargo/bin
cargo install --path .

# Or install with specific features
cargo install --path . --features "advanced-security"
```

## Project Structure

```
file-encryptor/
├── src/                    # Source code
│   ├── crypto/            # Cryptographic modules
│   ├── signature/         # Digital signature handling
│   ├── hardware/          # Device fingerprinting
│   ├── format/            # File format handling
│   ├── cli/              # Command-line interface
│   ├── security.rs       # Security utilities
│   ├── tests.rs          # Integration tests
│   ├── lib.rs            # Library interface
│   └── main.rs           # Application entry point
├── documentation/         # Documentation files
├── target/               # Build artifacts (generated)
├── Cargo.toml           # Project configuration
├── Cargo.lock           # Dependency lock file
├── README.md            # Main documentation
└── .gitignore           # Git ignore rules
```

## Configuration

### Cargo.toml Dependencies
The project uses the following key dependencies:

```toml
[dependencies]
# Cryptographic libraries
argon2 = "0.5"
aes-gcm = "0.10"
sha2 = "0.10"
ed25519-dalek = "2.0"
rand = "0.8"
zeroize = "1.6"

# CLI and parsing
clap = { version = "4.4", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# System information
sysinfo = "0.29"
uuid = { version = "1.4", features = ["v4"] }

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# File system operations
tokio = { version = "1.32", features = ["full"] }
```

### Environment Variables
```bash
# Optional: Set custom build profile
export RUSTFLAGS="-C target-cpu=native"

# Optional: Enable debug logging
export RUST_LOG=debug

# Optional: Custom temporary directory
export TEMP_DIR="/path/to/custom/temp"
```

## Development Setup

### 1. IDE Configuration
**Visual Studio Code:**
- Install the Rust extension (rust-lang.rust)
- Install the crates extension for dependency management
- Recommended settings:
  ```json
  {
    "rust-analyzer.cargo.loadOutDirsFromCheck": true,
    "rust-analyzer.procMacro.enable": true,
    "editor.formatOnSave": true
  }
  ```

**IntelliJ IDEA:**
- Install the Rust plugin
- Configure Rust toolchain path
- Enable external linter (clippy)

### 2. Development Tools
```bash
# Install clippy for linting
rustup component add clippy

# Install rustfmt for formatting
rustup component add rustfmt

# Install cargo-audit for security auditing
cargo install cargo-audit

# Install cargo-watch for development
cargo install cargo-watch
```

### 3. Development Workflow
```bash
# Continuous compilation
cargo watch -x build

# Continuous testing
cargo watch -x test

# Run with clippy
cargo clippy --all-targets --all-features

# Format code
cargo fmt

# Security audit
cargo audit
```

## Cross-Platform Building

### Windows from Linux/macOS:
```bash
# Install cross-compilation tools
rustup target add x86_64-pc-windows-gnu

# Build for Windows
cargo build --target x86_64-pc-windows-gnu --release
```

### Linux from Windows:
```bash
# Using WSL2
wsl
# Then follow Linux installation steps
```

### macOS:
```bash
# Build for different architectures
rustup target add aarch64-apple-darwin  # Apple Silicon
rustup target add x86_64-apple-darwin   # Intel Mac

# Build universal binary
cargo build --target aarch64-apple-darwin --release
cargo build --target x86_64-apple-darwin --release
```

## Container Deployment

### Docker Setup:
```dockerfile
FROM rust:1.70 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y openssl ca-certificates
COPY --from=builder /app/target/release/file-encryptor /usr/local/bin/

ENTRYPOINT ["file-encryptor"]
```

### Build and Run:
```bash
# Build container
docker build -t file-encryptor .

# Run container
docker run -v $(pwd):/data file-encryptor encrypt \
  --input /data/input.txt \
  --output /data/output.encrypted \
  --password "MyPassword123!"
```

## Performance Tuning

### Build Optimizations:
```toml
# Cargo.toml profile settings
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### Runtime Optimizations:
```bash
# Use native CPU instructions
export RUSTFLAGS="-C target-cpu=native"

# Enable link-time optimization
export RUSTFLAGS="-C lto=thin"
```

## Troubleshooting

### Common Build Issues:

**1. Missing dependencies:**
```bash
# Ubuntu/Debian
sudo apt install build-essential pkg-config libssl-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel
```

**2. Permission errors:**
```bash
# Fix cargo directory permissions
sudo chown -R $(whoami) ~/.cargo
```

**3. Compilation failures:**
```bash
# Clean build cache
cargo clean
cargo build --release
```

**4. Linking errors:**
```bash
# Install OpenSSL development libraries
# Ubuntu/Debian
sudo apt install libssl-dev

# macOS
brew install openssl
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig"
```

### Verification Steps:

1. **Check Rust installation:**
   ```bash
   rustc --version
   cargo --version
   rustup show
   ```

2. **Verify dependencies:**
   ```bash
   cargo check
   cargo tree
   ```

3. **Test functionality:**
   ```bash
   cargo test --release
   cargo run -- --help
   ```

## Updating the Project

### Update Dependencies:
```bash
# Check for outdated dependencies
cargo update

# Update specific crate
cargo update -p crate-name

# Security audit
cargo audit
```

### Update Rust:
```bash
# Update to latest stable
rustup update stable

# Update to specific version
rustup install 1.75.0
rustup default 1.75.0
```

## Uninstallation

### Remove Binary:
```bash
# Remove cargo-installed binary
cargo uninstall file-encryptor

# Remove manually compiled binary
rm /usr/local/bin/file-encryptor  # or ~/.cargo/bin/file-encryptor
```

### Remove Source:
```bash
# Remove project directory
rm -rf /path/to/file-encryptor

# Remove cargo cache (optional)
cargo cache --autoclean
```

### Remove Rust (if needed):
```bash
# Uninstall rustup
rustup self uninstall
```

This guide provides comprehensive instructions for installing, building, and maintaining the File Encryptor project across different platforms and environments.