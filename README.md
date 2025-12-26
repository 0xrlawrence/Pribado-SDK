# Pribado Seed Proxy SDK

**Zero-Knowledge Key Bridge SDK**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/pribado-seed-proxy-sdk.svg)](https://www.npmjs.com/package/pribado-seed-proxy-sdk)

> Securely manage Web3 seed phrases and private keys with client-side encryption and Oasis Sapphire TEEs.

The Pribado Seed Proxy SDK allows any wallet or application to create secure, encrypted endpoints for seed phrase and private key management. Your secrets are encrypted client-side and stored securely on Oasis Sapphire TEE or off-chain (L2S), accessible only with your password.

**V2.0.0:** Now supports both **Seed Phrases** and **Private Keys**!

---

## Why Seed Proxy?

**The Problem:**
- Seed phrases stored in plain text in wallet extensions
- Private keys vulnerable to malware and phishing
- One compromised device = all funds lost

**The Solution:**
- Keys encrypted client-side before storage
- Signing happens inside hardware TEE (Trusted Execution Environment)
- Real key NEVER leaves the secure enclave
- Proxy key ID can be safely used in applications
- **Auto-rotation** - Keys rotate after each use for maximum security

---

## Features

- **Client-Side Encryption** - Secrets are encrypted in the browser before transmission
- **Dual Support** - Store seed phrases (12/24 words) OR private keys (0x...)
- **Auto Key Rotation** - Proxy keys automatically rotate after each use
- **Multi-Storage** - Choose between Oasis Sapphire (TEE) or L2S (off-chain encrypted)
- **Easy Integration** - Simple HTTP-based API for any platform
- **Zero-Knowledge** - Server never sees your unencrypted secrets
- **L2S: No Gas Fees** - Off-chain storage for cost-sensitive applications

---

## Installation

```bash
npm install pribado-seed-proxy-sdk
# or
yarn add pribado-seed-proxy-sdk
# or
pnpm add pribado-seed-proxy-sdk
```

---

## Quick Start

### Register a Seed Phrase

```typescript
import { createSeedProxyClient } from 'pribado-seed-proxy-sdk';

const client = createSeedProxyClient({
  baseUrl: 'https://your-pribado-instance.com',
  defaultStorage: 'l2s'
});

const result = await client.registerVault({
  secret: 'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12',
  password: 'your-secure-password',
  label: 'My Main Wallet',
  ownerAddress: '0x...'
});

console.log('Save this proxy key:', result.proxyKeyId);
```

### Register a Private Key

```typescript
const result = await client.registerVault({
  secret: '0xa8b294d1c5977795c9be902d5a57210c458fbf42d7a091aa70a1a28c12747335',
  password: 'your-secure-password',
  label: 'Trading Bot Key',
  ownerAddress: '0x...',
  storageType: 'sapphire' // TEE storage for maximum security
});

console.log('Proxy key:', result.proxyKeyId);
// Key type is auto-detected as 'privateKey'
```

---

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR DEVICE                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐     ┌──────────────────┐     ┌──────────────┐ │
│  │   Wallet    │────▶│  Pribado SDK     │────▶│  Proxy Key   │ │
│  │             │     │                  │     │  priv_xxx    │ │
│  └─────────────┘     └────────┬─────────┘     └──────────────┘ │
└───────────────────────────────┼─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   OASIS SAPPHIRE (TEE)                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Your encrypted key stored here                          │  │
│  │  Signing happens INSIDE the hardware enclave             │  │
│  │  Real key NEVER exposed to anyone                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Usage

### Register a Vault

Store your seed phrase securely:

```typescript
const result = await client.registerVault({
  seedPhrase: 'your twelve word seed phrase here ...',
  password: 'minimum-6-chars',
  label: 'Wallet Name',
  ownerAddress: '0xYourWalletAddress',
  storageType: 'l2s' // 'l2s' (off-chain) or 'sapphire' (on-chain TEE)
});

if (result.success) {
  // IMPORTANT: Store this proxy key securely!
  // You'll need it + password to access your seed
  console.log('Proxy Key:', result.proxyKeyId);
}
```

### Authenticate (Login)

Recover your seed phrase and get a new rotation key:

```typescript
const result = await client.authenticate({
  proxyKeyId: 'priv_secret...',
  password: 'your-password'
});

if (result.success) {
  // Your decrypted seed phrase
  console.log('Seed:', result.seedPhrase);
  
  // IMPORTANT: Store the new key for next login!
  // The old key is now invalid
  console.log('New Key:', result.newProxyKeyId);
}
```

### Verify a Key

Check if a proxy key is valid before using:

```typescript
const result = await client.verifyKey({
  proxyKeyId: 'priv_...'
});

if (result.valid && result.isActive) {
  console.log('Key is valid and ready to use');
} else if (!result.isActive) {
  console.log('Key has been revoked or already used');
}
```

### Sign a Message

Sign messages using your stored seed:

```typescript
const result = await client.signMessage({
  proxyKeyId: 'priv_...',
  password: 'your-password',
  message: 'Hello, Web3!'
});

console.log('Signature:', result.signature);
// 0x1234...
```

### Sign a Transaction

Sign transactions without exposing your seed:

```typescript
import { SAPPHIRE_MAINNET_CHAIN_ID } from '@pribado/seed-proxy-sdk';

const result = await client.signTransaction({
  proxyKeyId: 'priv_...',
  password: 'your-password',
  transaction: {
    to: '0xRecipient...',
    value: '1000000000000000000', // 1 ROSE in wei
    chainId: SAPPHIRE_MAINNET_CHAIN_ID // 23294 (use 23295 for Testnet)
  }
});

// Broadcast the signed transaction
const txHash = await provider.sendTransaction(result.signedTransaction);
```

### List All Vaults

Get all vaults for an owner address:

```typescript
const vaults = await client.listVaults('0xOwnerAddress');

for (const vault of vaults) {
  console.log(`${vault.label}: ${vault.type}, Active: ${vault.isActive}`);
}
```

### Rotate Key Manually

Rotate a key without authentication:

```typescript
const result = await client.rotateKey({
  proxyKeyId: 'priv_old...',
  password: 'your-password'
});

console.log('New Key:', result.newProxyKeyId);
```

### Revoke a Key

Permanently disable a proxy key:

```typescript
const result = await client.revokeKey({
  proxyKeyId: 'priv_...',
  password: 'your-password'
});

if (result.success) {
  console.log('Key has been revoked');
}
```

---

## Storage Types

### L2S (Layer 2 Storage)
- **Off-chain** encrypted storage
- **No gas fees** for registration or rotation
- **Fast** operations
- **Proxy key format:** `priv_secret...`
- Best for: High-frequency use, cost-sensitive applications

### Sapphire (TEE)
- **On-chain** storage on Oasis Sapphire
- **Hardware-level** security via Trusted Execution Environment
- **Decentralized** and tamper-proof
- **Proxy key format:** `priv_...`
- Best for: Maximum security, regulatory compliance

---

## Oasis Sapphire Network

**Live Contract:** [`0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0`](https://explorer.oasis.io/mainnet/sapphire/address/0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0)

| Network | Chain ID | RPC URL |
|---------|----------|---------|
| Mainnet | 23294 | https://sapphire.oasis.io |

```typescript
import { SAPPHIRE_MAINNET_CHAIN_ID } from '@pribado/seed-proxy-sdk';
// SAPPHIRE_MAINNET_CHAIN_ID = 23294
```

### Configuration

The SDK connects to the official KeyBridge contract by default:

```typescript
import { CONTRACT_ADDRESS } from 'pribado-seed-proxy-sdk';

console.log(CONTRACT_ADDRESS); 
// 0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0
```

---

## Security Best Practices

1. **Never share your proxy key** - Treat it like a password
2. **Use strong passwords** - Minimum 8 characters, mix of letters/numbers/symbols
3. **Store new keys immediately** - Keys rotate after each use
4. **Revoke compromised keys** - If you suspect a breach, revoke immediately
5. **Use HTTPS** - Always connect to the API over HTTPS

---

## Error Handling

```typescript
import { SeedProxyError, SeedProxyErrorCode } from '@pribado/seed-proxy-sdk';

try {
  await client.authenticate({ ... });
} catch (error) {
  if (error instanceof SeedProxyError) {
    switch (error.code) {
      case SeedProxyErrorCode.INVALID_PASSWORD:
        console.log('Wrong password');
        break;
      case SeedProxyErrorCode.KEY_NOT_FOUND:
        console.log('Key does not exist');
        break;
      case SeedProxyErrorCode.KEY_INACTIVE:
        console.log('Key has been revoked');
        break;
      default:
        console.log('Error:', error.message);
    }
  }
}
```

---

## API Reference

### `createSeedProxyClient(config)`

Create a new client instance.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `baseUrl` | string | Yes | Base URL of the Pribado API |
| `apiKey` | string | No | API key for authentication |
| `defaultStorage` | 'sapphire' \| 'l2s' | No | Default storage type (default: 'l2s') |
| `timeout` | number | No | Request timeout in ms (default: 30000) |

### Exported Constants

```typescript
export const SAPPHIRE_MAINNET_CHAIN_ID = 23294;
export const CONTRACT_ADDRESS = '0x9B4aA4B40995bD93256E26706A12535851C4FD95';
export const VERSION = '1.0.0';
```

---

## Self-Hosting

You can self-host the Pribado API to have full control over your data:

```bash
# Clone the repository
git clone https://github.com/0xrlawrence/pribado.git

# Install dependencies
npm install

# Configure environment
cp .env.local.example .env.local
# Edit .env.local with your settings

# Run the server
npm run dev
```

---

## Documentation

- [Security Model](./docs/SECURITY.md)
- [Integration Guide](./docs/INTEGRATION.md)

---

## License

MIT License - Copyright (c) 2025 Ralph Lawrence Pecayo

---

## Links

- **Website:** [pribado.dev](https://pribado.dev)
- **GitHub:** [github.com/0xrlawrence/pribado](https://github.com/0xrlawrence/pribado)
- **Twitter:** [@0xrlawrence](https://twitter.com/0xrlawrence)

---

<p align="center">
  <sub>Built with  for Web3 privacy on Oasis Sapphire</sub>
</p>
