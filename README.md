# VPN9 App

<p align="center">
  <img src="src-tauri/icons/vpn9.png" alt="VPN9 Logo" width="128" height="128">
</p>

<p align="center">
  <strong>Zero-logs VPN service with anonymous accounts and open-source transparency</strong>
</p>

<p align="center">
  <a href="https://vpn9.com">Website</a> •
  <a href="#features">Features</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#development">Development</a> •
  <a href="#security">Security</a>
</p>

---

## Overview

VPN9 App is a cross-platform desktop and mobile VPN client built with [Tauri](https://tauri.app/) and [Rust](https://www.rust-lang.org/). It provides secure, anonymous VPN connections with a focus on privacy, transparency, and ease of use.

The application features a modern, responsive UI built with [Leptos](https://leptos.dev/) (Rust/WASM framework) and connects to VPN9's global server network to provide:

- **Anonymous account creation** - No email or personal information required
- **Zero-logs networking** - No connection or activity logs stored
- **Crypto-ready payments** - Privacy-focused payment options
- **Open-source transparency** - All client code is open for audit

## Features

### Core Functionality
- 🔐 **Passphrase-based Authentication** - Secure login with memorable passphrases
- 🌍 **Global Server Network** - Connect to VPN servers worldwide
- 🚀 **Fast & Lightweight** - Native performance with Rust backend
- 📱 **Cross-platform** - Works on Windows, macOS, Linux, iOS, and Android

### Security Features
- 🛡️ **Kill Switch** - Blocks internet if VPN disconnects (coming soon)
- 🔀 **Split Tunneling** - Route specific apps through VPN (coming soon)
- 🔒 **Secure Token Storage** - Uses OS keyring only (with AEAD-encrypted file fallback)
- 🆔 **Device Fingerprinting** - Hybrid device identification for account security

### Privacy Features
- 🕵️ **No Personal Data** - Anonymous accounts without email/phone
- 📊 **Zero Logs** - No connection or activity logging
- 💰 **Crypto Payments** - Privacy-focused payment methods
- 🔓 **Open Source** - Full transparency with auditable code

## Getting Started

### Prerequisites

- **Rust** (1.70 or later) - [Install Rust](https://rustup.rs/)
- **Node.js** (16 or later) - [Install Node.js](https://nodejs.org/)
- **Trunk** - Install with `cargo install trunk`
- **Tauri CLI** - Install with `cargo install tauri-cli`

#### Platform-specific Requirements

**Linux:**
```bash
sudo apt update
sudo apt install libwebkit2gtk-4.1-dev \
    build-essential \
    curl \
    wget \
    file \
    libssl-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev
```

**macOS:**
- Xcode Command Line Tools: `xcode-select --install`

**Windows:**
- [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- WebView2 (comes with Windows 11 or Edge)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/vpn9/vpn9-app.git
cd vpn9-app
```

2. **Install dependencies:**
```bash
# Install Rust/WASM target
rustup target add wasm32-unknown-unknown

# Install development tools
cargo install trunk tauri-cli
```

3. **Run in development mode:**
```bash
cargo tauri dev
```

4. **Build for production:**
```bash
cargo tauri build
```

The built application will be in `src-tauri/target/release/bundle/`.

## Development

### Project Structure

```
vpn9-app/
├── src/                    # Frontend (Leptos/WASM)
│   ├── app.rs             # Main UI components
│   └── main.rs            # Frontend entry point
├── src-tauri/             # Backend (Tauri/Rust)
│   ├── src/
│   │   ├── lib.rs         # Core backend logic
│   │   └── main.rs        # Tauri entry point
│   ├── icons/             # Application icons
│   └── tauri.conf.json    # Tauri configuration
├── index.html             # HTML template
├── styles.css             # Application styles
├── Cargo.toml             # Rust workspace config
└── Trunk.toml             # Frontend build config
```

### Architecture

The application uses a modern architecture with clear separation of concerns:

- **Frontend**: Leptos (Rust compiled to WASM) for reactive UI
- **Backend**: Tauri with Rust for system integration and VPN logic
- **Communication**: Type-safe IPC between frontend and backend
- **State Management**: Reactive signals for UI state

### Key Components

#### Authentication System
- Passphrase-based login with device fingerprinting
- JWT tokens for session management
- Secure storage using OS keyring only (with optional AEAD-encrypted file fallback)
- Automatic token refresh

#### VPN Connection Manager
- Server selection with real-time load information
- Connection state management
- Future support for WireGuard and OpenVPN protocols

#### Security Features
- Hybrid device identification (OS ID → UUID → Hardware fingerprint)
- OS keyring token storage (optional AEAD-encrypted file fallback)
- Secure API communication with VPN9 backend

### Development Commands

```bash
# Run development server
cargo tauri dev

# Build for production
cargo tauri build

# Run frontend only (for UI development)
trunk serve

# Check Rust code
cargo check

# Run linter
cargo clippy

# Format code
cargo fmt
```


### Logging

- Backend uses `tauri-plugin-log` and emits one-line JSON logs.
- Fields: `ts`, `level`, `target`, `module_path`, `file`, `line`, `msg`.
- Level: DEBUG in dev (`cargo tauri dev`), INFO in release (`cargo tauri build`).
- View logs in the terminal running the app; packaged apps forward to OS logs depending on platform.
- To change level or destinations, adjust the builder in `src-tauri/src/lib.rs`.

### API Endpoints

The app connects to VPN9's API at `https://vpn9.com/api/v1/`:

- `POST /auth/token` - Authenticate with passphrase
- `POST /auth/refresh` - Refresh access token
- `GET /relays` - Get list of VPN servers

## Building

### Desktop Builds

```bash
# Windows (.msi)
cargo tauri build --target x86_64-pc-windows-msvc

# macOS (.app, .dmg)
cargo tauri build --target x86_64-apple-darwin
cargo tauri build --target aarch64-apple-darwin

# Linux (.deb, .AppImage)
cargo tauri build --target x86_64-unknown-linux-gnu
```

### Mobile Builds

Mobile support is coming soon. The app is designed with mobile in mind, featuring:
- Responsive UI that adapts to small screens
- Touch-friendly controls
- iOS and Android platform support via Tauri

## Security

### Token Storage

By default, the application stores tokens exclusively in the OS keyring:

1. **OS Keyring**: Windows Credential Manager, macOS Keychain, or Linux Secret Service
2. **No File Fallback**: If the keyring is unavailable, token persistence fails safely
3. **Migration**: On logout, the app cleans up any legacy token file from older versions

### Device Identification

Three-tier device identification system:
1. **OS Machine ID**: Most reliable, platform-specific
2. **Persistent UUID**: Stored securely, survives reinstalls
3. **Hardware Fingerprint**: Last resort, based on system specs

### Best Practices

- No hardcoded secrets or API keys
- All sensitive data encrypted at rest
- Secure IPC communication between frontend and backend
- Regular security updates and dependency audits

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPLv3). See the `LICENSE` file for the full license text. By contributing, you agree that your contributions are licensed under the same terms.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Use `cargo clippy` for linting
- Write tests for new features
- Update documentation as needed

## Support

- **Issues**: [GitHub Issues](https://github.com/vpn9/vpn9-app/issues)

## Acknowledgments

Built with:
- [Tauri](https://tauri.app/) - Build smaller, faster, and more secure desktop applications
- [Leptos](https://leptos.dev/) - Build fast web applications with Rust
- [Rust](https://www.rust-lang.org/) - A language empowering everyone to build reliable and efficient software

---

<p align="center">
  Made with ❤️ by the VPN9 team
</p>
