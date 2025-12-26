#Security Model

This document describes the security architecture of the Pribado Seed Proxy SDK.

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Cryptographic Design](#cryptographic-design)
3. [Storage Types](#storage-types)
4. [Key Lifecycle](#key-lifecycle)
5. [Authentication](#authentication)
6. [Key Rotation](#key-rotation)
7. [Known Limitations](#known-limitations)

---

## Threat Model

### What We Protect Against

| Threat | Protection |
|--------|------------|
| Malware reading seed phrases from storage |  Keys encrypted with AES-256-GCM client-side |
| Man-in-the-middle attacks |  All data encrypted end-to-end |
| Server-side data breaches |  Server only sees encrypted blobs |
| Phishing attacks |  Real key never exposed during normal use |
| Key reuse attacks |  Auto-rotation after each use |
| Replay attacks |  Each authentication invalidates the previous key |
| Brute-force attacks |  PBKDF2 with 100,000 iterations |

### Trust Assumptions

1. **Oasis Sapphire TEE** - We trust the Oasis Sapphire hardware TEE (Intel SGX-based) to execute code confidentially
2. **User's Device at Registration** - The device must be secure during initial seed phrase entry
3. **User's Password Strength** - Strong passwords are essential for security
4. **Browser Integrity** - The browser must not be compromised during key entry

---

## Cryptographic Design

### Client-Side Encryption

All encryption happens in the browser/client **before** any data is sent to the server.

```
Password → PBKDF2-SHA256 (100,000 iterations) → 256-bit AES Key
Seed Phrase + AES Key → AES-256-GCM → Encrypted Blob
```

### Encryption Parameters

```
Algorithm: AES-256-GCM
Salt: 128-bit random
IV: 96-bit random  
Tag: 128-bit authentication tag (built into GCM)
KDF: PBKDF2-SHA256 with 100,000 iterations
```

### Encrypted Data Format

The encrypted seed phrase is stored as a base64-encoded blob:

```
[Salt: 16 bytes][IV: 12 bytes][Ciphertext + AuthTag: variable]
```

This format ensures:
- Each encryption uses a unique salt and IV
- The authentication tag prevents tampering
- No plaintext metadata is exposed

---

## Storage Types

### L2S (Layer 2 Storage)

**Off-chain encrypted storage** for maximum speed and no gas fees.

| Aspect | Details |
|--------|---------|
| Storage Location | Server-side SQLite database |
| Encryption | AES-256-GCM (client-side) |
| Key Format | `priv_secret{random_hex}` |
| Gas Cost | None |
| Speed | Instant |
| Best For | High-frequency use, cost-sensitive apps |

### Sapphire (TEE)

**On-chain storage** on Oasis Sapphire Trusted Execution Environment.

| Aspect | Details |
|--------|---------|
| Storage Location | Oasis Sapphire smart contract |
| Encryption | Dual: client-side + TEE hardware |
| Key Format | `priv_{random_hex}` |
| Gas Cost | ~0.1 ROSE per operation |
| Speed | ~6 seconds (block confirmation) |
| Best For | Maximum security, regulatory compliance |

### Sapphire TEE Security

When using Sapphire storage, additional protections apply:

1. **Confidential Smart Contracts** - Contract state is encrypted in hardware
2. **Secure Random Generation** - Hardware-backed randomness
3. **Encrypted Memory** - Data encrypted while in use
4. **Key Material in TEE Only** - Decryption keys never leave the enclave

---

## Key Lifecycle

### 1. Registration

```
User enters seed phrase
    ↓
SDK encrypts seed phrase client-side (AES-256-GCM)
    ↓
SDK generates random proxy key ID
    ↓
Encrypted blob + key hash sent to server/contract
    ↓
Proxy key ID returned to user
    ↓
Original seed phrase cleared from memory
```

**Security Properties:**
- Seed phrase never leaves the device unencrypted
- Server only receives encrypted blob
- No way to recover seed without password

### 2. Authentication (Login)

```
User provides proxy key ID + password
    ↓
SDK sends key hash to server
    ↓
Server returns encrypted blob
    ↓
SDK decrypts blob client-side
    ↓
***KEY ROTATION: New proxy key generated***
    ↓
Old key invalidated, new key stored
    ↓
Seed phrase + new proxy key returned
```

**Security Properties:**
- Each authentication generates a new key
- Old key immediately invalidated
- Prevents replay attacks

### 3. Key Rotation

Every authentication automatically rotates the key:

1. User authenticates with `priv_abc123...`
2. Authentication succeeds, seed phrase decrypted
3. New key `priv_def456...` generated
4. Old key hash invalidated on server
5. New key hash stored
6. User receives seed + **new key for next login**

 **Critical:** Users must store the new key, or they lose access!

### 4. Revocation

```
User requests revocation
    ↓
SDK sends key hash to server
    ↓
Key marked as inactive in database
    ↓
Key can never be used again
```

**For Sapphire:** The vault is deactivated on-chain and the encrypted data is deleted.

---

## Authentication

### Password-Only Authentication

The Seed Proxy SDK uses password-only authentication (unlike the original KeyBridge which used wallet signature + password). This simplifies integration while maintaining security through:

1. **Strong password requirements** - Minimum 6 characters (recommend 12+)
2. **PBKDF2 key stretching** - 100,000 iterations makes brute-force expensive
3. **Auto-rotation** - Even if attackers observe one authentication, the key is already invalidated

### Auth Flow

```typescript
// User provides password
const password = getUserInput();

// Password used to derive decryption key
// PBKDF2(password, salt) → AES key
// AES key decrypts → seed phrase
```

---

## Key Rotation

### Why Auto-Rotation?

1. **Forward Secrecy** - Compromising one key doesn't compromise future sessions
2. **Replay Prevention** - Old authentication attempts fail immediately
3. **Key Freshness** - Regular key updates limit exposure window

### Rotation Mechanics

| Event | Rotation Occurs? |
|-------|------------------|
| Registration | N/A (initial key) |
| Authentication (login) |  Yes - mandatory |
| Message signing |  Yes - key consumed |
| Transaction signing |  Yes - key consumed |
| Key verification |  No - read-only |
| Key revocation |  No - key destroyed |

### Rotation Storage

For **L2S**, rotation updates the key hash in the SQLite database.

For **Sapphire**, rotation calls the smart contract's `rotateKey` function:

```solidity
function rotateKey(bytes32 oldPrivKey, bytes32 newKeyHash) returns (uint256 vaultIndex);
```

---

## Known Limitations

### 1. Initial Seed Entry

The user must enter their seed phrase on a secure device. If the device is compromised at this moment, the key could be leaked.

**Mitigation:** 
- Encourage users to register keys on a clean, secure device
- Clear seed phrase from memory immediately after encryption

### 2. Password Strength

Security depends on password strength. Weak passwords can be brute-forced if the encrypted blob is obtained.

**Mitigation:** 
- Enforce minimum 6 characters (recommend 12+)
- Use 100,000 PBKDF2 iterations
- Consider Argon2id for future versions

### 3. Key Storage Responsibility

Users must securely store their proxy keys and update them after each login.

**Mitigation:**
- Clear UI warnings about key rotation
- Recommend secure storage (password managers, secure notes)
- Return new key prominently in authentication response

### 4. Single Point of Trust (L2S)

For L2S storage, the server operator has access to encrypted blobs. While they cannot decrypt without the password, a malicious operator could:
- Delete the encrypted data (denial of service)
- Log failed authentication attempts

**Mitigation:**
- Use Sapphire storage for maximum trust minimization
- Self-host the Pribado server for full control

### 5. TEE Side-Channel Attacks

While rare, TEE implementations can be vulnerable to side-channel attacks (e.g., Spectre, Meltdown).

**Mitigation:** 
- Oasis Sapphire is designed to mitigate these
- The attack window is very brief (during signing)
- Updates are applied as patches become available

---

## Audit Status

| Component | Status |
|-----------|--------|
| Core SDK Crypto | ⏳ Pending |
| Smart Contract (V9) | ⏳ Pending |
| API Security | ⏳ Pending |

---

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

- **Email**: security@pribado.dev
- **GitHub**: [Private vulnerability report](https://github.com/0xrlawrence/pribado/security)

Do **NOT** disclose vulnerabilities publicly before giving us 90 days to address them.

---

## Further Reading

- [Oasis Sapphire Documentation](https://docs.oasis.io/dapp/sapphire/)
- [AES-GCM NIST Standard](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [PBKDF2 RFC 2898](https://tools.ietf.org/html/rfc2898)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
