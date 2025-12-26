#Integration Guide

This guide explains how to integrate the Pribado Seed Proxy SDK into your Web3 wallet or application.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Browser Applications](#browser-applications)
4. [Node.js / Server-Side](#nodejs--server-side)
5. [React Integration](#react-integration)
6. [Mobile Wallets](#mobile-wallets)
7. [Security Considerations](#security-considerations)

---

## Overview

The Pribado Seed Proxy SDK allows wallets to:

1. **Store keys securely** - Encrypted on Oasis Sapphire TEE or off-chain (L2S)
2. **Authenticate users** - Using proxy keys instead of raw seed phrases
3. **Sign transactions** - Without exposing the real key
4. **Auto-rotate keys** - For enhanced security

### Key Flow

```
User Seed Phrase → Client-Side Encrypt → Store → Return Proxy Key ID
```

### Authentication Flow

```
Proxy Key ID + Password → Verify → Decrypt → Return Seed + New Rotated Key
```

---

## Quick Start

### Installation

```bash
npm install pribado-seed-proxy-sdk ethers
```

### Basic Integration

```typescript
import { createSeedProxyClient } from 'pribado-seed-proxy-sdk';

// Initialize with your Pribado instance URL
const client = createSeedProxyClient({
  baseUrl: 'https://your-pribado-instance.com', // or http://localhost:3000
  defaultStorage: 'l2s' // 'l2s' (off-chain) or 'sapphire' (on-chain TEE)
});

// Register a new vault
async function registerUserKey(seedPhrase: string, password: string, userAddress: string) {
  const result = await client.registerVault({
    seedPhrase,
    password,
    label: 'My Wallet',
    ownerAddress: userAddress,
    storageType: 'l2s'
  });
  
  if (result.success) {
    // IMPORTANT: Store this proxy key securely for future logins
    console.log('Proxy Key ID:', result.proxyKeyId);
    return result.proxyKeyId;
  }
  
  throw new Error(result.error);
}

// Authenticate (login) with a proxy key
async function loginWithProxyKey(proxyKeyId: string, password: string) {
  const result = await client.authenticate({
    proxyKeyId,
    password
  });
  
  if (result.success) {
    console.log('Seed phrase:', result.seedPhrase);
    console.log('New key for next login:', result.newProxyKeyId);
    
    // IMPORTANT: Store the new proxy key for the next login!
    // The old key is now invalid
    return {
      seedPhrase: result.seedPhrase,
      newProxyKeyId: result.newProxyKeyId
    };
  }
  
  throw new Error(result.error);
}
```

---

## Browser Applications

### Vanilla JavaScript

```html
<script type="module">
  import { createSeedProxyClient } from 'https://cdn.jsdelivr.net/npm/pribado-seed-proxy-sdk/dist/index.mjs';
  
  const client = createSeedProxyClient({
    baseUrl: 'https://your-pribado-instance.com'
  });
  
  document.getElementById('registerBtn').onclick = async () => {
    const seedPhrase = document.getElementById('seedPhrase').value;
    const password = document.getElementById('password').value;
    const address = document.getElementById('address').value;
    
    try {
      const result = await client.registerVault({
        seedPhrase,
        password,
        ownerAddress: address,
        label: 'My Vault'
      });
      
      alert('Proxy Key: ' + result.proxyKeyId);
    } catch (error) {
      alert('Error: ' + error.message);
    }
  };
</script>
```

### With Wallet Connection (ethers.js)

```typescript
import { createSeedProxyClient, SAPPHIRE_MAINNET_CHAIN_ID } from 'pribado-seed-proxy-sdk';
import { ethers } from 'ethers';

const client = createSeedProxyClient({
  baseUrl: 'https://your-pribado-instance.com'
});

// Connect wallet
const provider = new ethers.BrowserProvider(window.ethereum);
const signer = await provider.getSigner();
const address = await signer.getAddress();

// Register vault
async function registerVault(seedPhrase: string, password: string) {
  return client.registerVault({
    seedPhrase,
    password,
    ownerAddress: address,
    label: 'My Wallet'
  });
}

// Sign transaction using vault seed
async function signAndSend(proxyKeyId: string, password: string, to: string, value: string) {
  const result = await client.signTransaction({
    proxyKeyId,
    password,
    transaction: {
      to,
      value: ethers.parseEther(value).toString(),
      chainId: SAPPHIRE_MAINNET_CHAIN_ID
    }
  });
  
  // Broadcast signed transaction
  const txResponse = await provider.broadcastTransaction(result.signedTransaction);
  return txResponse;
}
```

---

## Node.js / Server-Side

```typescript
import { createSeedProxyClient } from '@pribado/seed-proxy-sdk';

const client = createSeedProxyClient({
  baseUrl: process.env.PRIBADO_API_URL || 'http://localhost:3000',
  apiKey: process.env.PRIBADO_API_KEY // Optional
});

// Example: CLI Tool
async function main() {
  const proxyKeyId = process.argv[2];
  const password = process.argv[3];
  
  // Verify key first
  const verification = await client.verifyKey({ proxyKeyId });
  
  if (!verification.valid || !verification.isActive) {
    console.error('Key is invalid or has been revoked');
    process.exit(1);
  }
  
  // Authenticate
  const result = await client.authenticate({
    proxyKeyId,
    password
  });
  
  if (result.success) {
    console.log(' Authentication successful');
    console.log('New proxy key:', result.newProxyKeyId);
    // Use result.seedPhrase to derive wallet...
  }
}

main().catch(console.error);
```

---

## React Integration

### Custom Hook

```tsx
// hooks/useSeedProxy.ts
import { useState, useCallback, useMemo } from 'react';
import { 
  createSeedProxyClient, 
  SeedProxyError,
  SeedProxyErrorCode
} from '@pribado/seed-proxy-sdk';

export function useSeedProxy(baseUrl: string) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const client = useMemo(() => createSeedProxyClient({ baseUrl }), [baseUrl]);
  
  const registerVault = useCallback(async (
    seedPhrase: string,
    password: string,
    ownerAddress: string,
    label?: string
  ) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const result = await client.registerVault({
        seedPhrase,
        password,
        ownerAddress,
        label
      });
      return result;
    } catch (e) {
      const message = e instanceof SeedProxyError ? e.message : 'Registration failed';
      setError(message);
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [client]);
  
  const authenticate = useCallback(async (proxyKeyId: string, password: string) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const result = await client.authenticate({ proxyKeyId, password });
      return result;
    } catch (e) {
      const message = e instanceof SeedProxyError ? e.message : 'Authentication failed';
      setError(message);
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [client]);
  
  const verifyKey = useCallback(async (proxyKeyId: string) => {
    return client.verifyKey({ proxyKeyId });
  }, [client]);
  
  return {
    registerVault,
    authenticate,
    verifyKey,
    isLoading,
    error
  };
}
```

### Component Example

```tsx
// components/VaultLogin.tsx
import { useState } from 'react';
import { useSeedProxy } from '../hooks/useSeedProxy';

export function VaultLogin({ onSuccess }: { onSuccess: (seed: string) => void }) {
  const [proxyKeyId, setProxyKeyId] = useState('');
  const [password, setPassword] = useState('');
  const { authenticate, isLoading, error } = useSeedProxy('http://localhost:3000');
  
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const result = await authenticate(proxyKeyId, password);
      
      if (result.success && result.seedPhrase) {
        // Store new proxy key for next login
        localStorage.setItem('proxyKeyId', result.newProxyKeyId || '');
        
        // Callback with seed phrase
        onSuccess(result.seedPhrase);
      }
    } catch (err) {
      // Error is handled by the hook
    }
  };
  
  return (
    <form onSubmit={handleLogin}>
      <input
        type="text"
        placeholder="Proxy Key ID (priv_...)"
        value={proxyKeyId}
        onChange={(e) => setProxyKeyId(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
      {error && <p className="error">{error}</p>}
    </form>
  );
}
```

---

## Mobile Wallets

### React Native

```typescript
import { createSeedProxyClient } from '@pribado/seed-proxy-sdk';
import * as SecureStore from 'expo-secure-store';

const client = createSeedProxyClient({
  baseUrl: 'https://your-pribado-instance.com'
});

// Store proxy key securely
async function saveProxyKey(proxyKeyId: string) {
  await SecureStore.setItemAsync('pribado_proxy_key', proxyKeyId);
}

// Retrieve proxy key
async function getProxyKey(): Promise<string | null> {
  return SecureStore.getItemAsync('pribado_proxy_key');
}

// Login flow
async function login(password: string): Promise<string> {
  const proxyKeyId = await getProxyKey();
  
  if (!proxyKeyId) {
    throw new Error('No proxy key stored. Please register first.');
  }
  
  const result = await client.authenticate({
    proxyKeyId,
    password
  });
  
  if (result.success && result.newProxyKeyId) {
    // Update stored key for next login
    await saveProxyKey(result.newProxyKeyId);
    return result.seedPhrase!;
  }
  
  throw new Error(result.error || 'Login failed');
}
```

---

## Security Considerations

### 1. Password Requirements

Always enforce strong passwords:

```typescript
function validatePassword(password: string): { valid: boolean; message?: string } {
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain a number' };
  }
  return { valid: true };
}
```

### 2. Store New Keys Immediately

After authentication, the old key is invalidated. Always store the new key:

```typescript
const result = await client.authenticate({ proxyKeyId, password });

if (result.success) {
  // CRITICAL: Store new key before doing anything else
  await secureStorage.set('proxyKeyId', result.newProxyKeyId);
  
  // Now use the seed phrase...
}
```

### 3. Verify Keys Before Use

Always verify a key is valid before attempting authentication:

```typescript
const verification = await client.verifyKey({ proxyKeyId });

if (!verification.valid) {
  throw new Error('Key does not exist');
}

if (!verification.isActive) {
  throw new Error('Key has been revoked or already used');
}

// Safe to authenticate
const result = await client.authenticate({ proxyKeyId, password });
```

### 4. Handle Errors Gracefully

```typescript
import { SeedProxyError, SeedProxyErrorCode } from 'pribado-seed-proxy-sdk';

try {
  await client.authenticate({ proxyKeyId, password });
} catch (error) {
  if (error instanceof SeedProxyError) {
    switch (error.code) {
      case SeedProxyErrorCode.INVALID_PASSWORD:
        showError('Incorrect password. Please try again.');
        break;
      case SeedProxyErrorCode.KEY_NOT_FOUND:
        showError('Key not found. It may have been revoked.');
        break;
      case SeedProxyErrorCode.KEY_INACTIVE:
        showError('This key has already been used. Check for a newer key.');
        break;
      case SeedProxyErrorCode.NETWORK_ERROR:
        showError('Network error. Please check your connection.');
        break;
      default:
        showError('An error occurred. Please try again.');
    }
  }
}
```

### 5. Clear Sensitive Data

Clear seed phrases from memory after use:

```typescript
let seedPhrase = result.seedPhrase;

try {
  // Use the seed phrase...
  const wallet = ethers.Wallet.fromPhrase(seedPhrase);
  // ...
} finally {
  // Clear from memory (helps with garbage collection)
  seedPhrase = '';
}
```

---

## Support

- **Documentation**: [pribado.dev/docs](https://pribado.dev/docs)
- **GitHub Issues**: [github.com/0xrlawrence/pribado/issues](https://github.com/0xrlawrence/pribado/issues)
- **Twitter**: [@0xrlawrence](https://twitter.com/0xrlawrence)
