# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kubidm is a simple, secure, and fast identity management platform. It provides an LDAP-compatible directory service, OAuth2/OIDC authentication, RADIUS integration, and Unix integration for PAM/NSS.

**Tech Stack**: Rust (stable channel), Cargo workspace, Python (pykubidm), JavaScript (Web UI), Docker multi-arch builds, mdBook documentation.

**Components**:
- `server/daemon` - Main Kubidm server (kubidmd)
- `server/core` - Web UI and HTTP API
- `server/lib` - Core library
- `server/testkit` - Integration testing framework
- `libs/client` - Kubidm client SDK
- `libs/crypto` - Cryptographic utilities
- `libs/proto` - Protocol definitions
- `tools/cli` - Kubidm CLI tools
- `unix_integration/` - PAM/NSS modules
- `pykubidm/` - Python SDK
- `rlm_python/` - RADIUS module

## Essential Commands

### Development Workflow

```bash
# Lint and format check
make precommit

# Run cargo test
make test

# Run dev server (insecure, for testing)
make run

# Build Docker images locally
make build/kubidmd

# Build multi-arch Docker images and push
make buildx/kubidmd

# Spell check
make codespell

# Format markdown docs
make doc/format

# Fix markdown formatting
make doc/format/fix
```

### Python (pykubidm)

```bash
# Run all Python tests (pytest + mypy + ruff)
make test/pykubidm

# Run pytest only
make test/pykubidm/pytest

# Run mypy type check
make test/pykubidm/mypy

# Run ruff lint
make test/pykubidm/lint

# Run with coverage
make test/pykubidm/coverage
```

### Documentation

```bash
# Build the Kubidm book
make book

# Build Rust docs
make doc

# Build pykubidm docs (mkdocs)
make docs/pykubidm/build

# Serve pykubidm docs locally
make docs/pykubidm/serve
```

### Release

```bash
# Build CLI release binary (set KUBIDM_BUILD_PROFILE)
make release/kubidm

# Build daemon release binary
make release/kubidmd

# Check outdated dependencies
make prep
```

## Architecture

### Workspace Structure

**Libraries** (`libs/`):
- `client` - Kubidm client SDK for connecting to servers
- `crypto` - Cryptographic operations (password hashing, encryption)
- `proto` - SCIM and internal protocol definitions
- `scim_proto` - SCIM protocol types
- `sketching` - Logging and tracing setup
- `users` - User-related utilities
- `file_permissions` - File permission handling
- `profiles` - Build profile configuration

**Server** (`server/`):
- `daemon` - Main server binary (kubidmd)
- `core` - HTTP API, Web UI, OAuth2 endpoints
- `lib` - Core server logic (authentication, identity management)
- `lib-macros` - Proc macros for server
- `testkit` - Integration testing utilities
- `testkit-macros` - Test macros

**Tools** (`tools/`):
- `cli` - Kubidm CLI (kubidm command)
- `orca` - Load testing tool
- `iam_migrations/ldap` - LDAP migration tool
- `iam_migrations/freeipa` - FreeIPA migration tool
- `device_flow` - OAuth2 device flow helper
- `mail_sender` - Email notification sender

**Unix Integration** (`unix_integration/`):
- `resolver` - Unix resolver daemon
- `pam_kubidm` - PAM module
- `nss_kubidm` - NSS module
- `common` - Shared Unix integration code

**Python** (`pykubidm/`):
- Kubidm Python SDK with async support
- Uses uv for dependency management
- Strict mypy type checking

## Development Practices

### Code Style

- **Imports**: At top-level, grouped: std -> external crates -> internal crates
- **Rust formatting**: Use `cargo fmt`, configured in `.rustfmt.toml`
- **Clippy**: Zero warnings required, configured in `clippy.toml`
- **Disallowed types**: HashMap/HashSet (use BTreeMap/BTreeSet for determinism)
- **Disallowed methods**: `OffsetDateTime::now_utc` (inject time for testability)
- **Async**: Never block Tokio runtime; use async patterns
- **Error handling**: Use proper error types, avoid unwrap in production code

### Testing Strategy

- **Unit tests**: In-module tests with `#[cfg(test)]`
- **Integration tests**: Use `server/testkit` framework
- **Python tests**: pytest with async support, mypy strict mode

### Docker Builds

- Multi-arch: amd64, arm64
- Registry: ghcr.io/pando85/kubidm/*
- Build profile: `container_generic`
- Use `CONTAINER_IMAGE_ARCH` for cross-compilation

### Release Workflow

1. Update version in Cargo.toml
2. Run `make prep` to check outdated/audit
3. Update RELEASE_NOTES.md
4. Build release binaries
5. Build and push Docker images with version tags

## CI/CD

- **Linting**: clippy, rustfmt, codespell, ESLint, Prettier, ruff, mypy
- **Testing**: Rust tests, Python tests, Windows builds
- **Docker**: Multi-arch builds on PRs and pushes
- **Docs**: mdBook deployed to GitHub Pages

## Common Pitfalls

- Using `HashMap`/`HashSet` instead of `BtreeMap`/`BTreeSet`
- Calling `OffsetDateTime::now_utc` directly (breaks testability)
- Blocking calls in async code
- Forgetting to run `make precommit` before pushing
- Missing spell check fixes (run `make codespell`)

## Environment Variables

- `KUBIDM_BUILD_PROFILE`: Build profile (developer, container_generic, release)
- `KUBIDM_FEATURES`: Additional Cargo features
- `CONTAINER_IMAGE_ARCH`: Docker build architectures
- `BOOK_VERSION`: Documentation version for book builds

## Container Registry

- Images: `ghcr.io/pando85/kubidm/server`, `ghcr.io/pando85/kubidm/tools`, `ghcr.io/pando85/kubidm/radius`
- Tags: `devel` (latest development), version-specific for releases
