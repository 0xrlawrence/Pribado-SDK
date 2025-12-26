# Changelog

All notable changes to the Pribado Seed Proxy SDK will be documented in this file.

## [2.0.0] - 2025-12-26

### Added
- **Private Key Support** - SDK now supports storing Ethereum private keys (0x + 64 hex chars) in addition to seed phrases
- **Auto-Detection** - SDK automatically detects whether input is a seed phrase or private key
- **KeyType Field** - New `keyType` field in VaultInfo ('seed' | 'privateKey')
- **KEY_TYPE_SEED** and **KEY_TYPE_PRIVATE_KEY** constants exported
- **KeyType** TypeScript type exported
- **INVALID_PRIVATE_KEY** error code for validation errors

### Changed
- **Contract Upgrade** - Now uses KeyBridgeV9 contract (`0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0`)
- **RegisterVaultParams** - Added `secret` field (use instead of deprecated `seedPhrase`)
- **RegisterVaultParams** - Added optional `keyType` field for explicit type setting
- Updated all documentation to reflect V9 changes

### Deprecated
- `seedPhrase` parameter in RegisterVaultParams - use `secret` instead (still works for backward compatibility)

### Security
- Same AES-256-GCM encryption for both seed phrases and private keys
- Both types receive identical protection on Oasis Sapphire TEE

---

## [1.0.0] - 2025-12-15

### Added
- Initial release of Pribado Seed Proxy SDK
- Client-side AES-256-GCM encryption
- Support for L2S (off-chain) and Sapphire (on-chain TEE) storage
- Auto key rotation after each authentication
- Full TypeScript support with type definitions
- Comprehensive documentation

### Features
- `registerVault()` - Register new seed phrase vaults
- `authenticate()` - Recover seed phrase with auto-rotation
- `signMessage()` - Sign messages using stored seed
- `signTransaction()` - Sign transactions using stored seed
- `verifyKey()` - Check if a proxy key is valid
- `rotateKey()` - Manually rotate a proxy key
- `revokeKey()` - Permanently disable a proxy key
- `listVaults()` - List all vaults for an owner

---

## Version History

| Version | Date | Contract | Key Features |
|---------|------|----------|--------------|
| 2.0.0 | 2025-12-26 | KeyBridgeV9 | Private key support, auto-detection |
| 1.0.0 | 2025-12-15 | KeyBridgeV8 | Initial release |
