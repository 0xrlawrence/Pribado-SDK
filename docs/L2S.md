# L2S (Layer 2 Storage) Reference

This document describes the L2S off-chain storage system used by the Pribado Seed Proxy SDK.

---

## Table of Contents

1. [Overview](#overview)
2. [Why L2S?](#why-l2s)
3. [Database Schema](#database-schema)
4. [Data Flow](#data-flow)
5. [API Endpoints](#api-endpoints)
6. [Security Considerations](#security-considerations)
7. [Self-Hosting](#self-hosting)

---

## Overview

L2S (Layer 2 Storage) is an off-chain encrypted storage system that provides:

- **No gas fees** - All operations are free
- **Instant operations** - No blockchain confirmation needed
- **Client-side encryption** - Server only stores encrypted blobs
- **SQLite backend** - Simple, portable, reliable storage

L2S keys are identified by the prefix `priv_secret` (vs `priv_` for Sapphire on-chain).

---

## Why L2S?

| Feature | L2S (Off-chain) | Sapphire (On-chain) |
|---------|-----------------|---------------------|
| Gas Cost | None | ~0.1 ROSE per tx |
| Speed | Instant | ~6 seconds |
| Storage Location | Server SQLite | Blockchain |
| Encryption | Client-side AES-256 | Client + TEE hardware |
| Trust Model | Trust server operator | Trust TEE hardware |
| Decentralization | Centralized | Decentralized |
| Best For | High-frequency, cost-sensitive | Maximum security |

**Use L2S when:**
- Gas costs are a concern
- Speed is critical
- You control the server (self-hosting)
- Building prototypes or testing

**Use Sapphire when:**
- Maximum security is required
- Decentralization is important
- Regulatory compliance needed
- You don't trust server operators

---

## Database Schema

L2S uses SQLite with the following tables:

### sdk_vaults Table

Stores encrypted vaults for SDK users.

```sql
CREATE TABLE sdk_vaults (
    id              TEXT PRIMARY KEY,      -- Unique ID (sdk_timestamp)
    proxy_key_id    TEXT UNIQUE,           -- The full proxy key (priv_secret...)
    key_hash        TEXT UNIQUE,           -- Keccak256 hash for lookups
    encrypted_seed  TEXT,                  -- Base64-encoded encrypted blob
    label           TEXT,                  -- Human-readable label
    owner           TEXT,                  -- Owner wallet address
    storage_type    TEXT DEFAULT 'l2s',    -- Always 'l2s' for this table
    created_at      INTEGER,               -- Unix timestamp (ms)
    last_used       INTEGER DEFAULT 0,     -- Unix timestamp (ms)
    is_active       INTEGER DEFAULT 1      -- 1 = active, 0 = revoked
);
```

### l2s_vaults Table

Stores vaults for the main Pribado application.

```sql
CREATE TABLE l2s_vaults (
    id              TEXT PRIMARY KEY,      -- Unique ID (l2s_timestamp)
    label           TEXT,                  -- Human-readable label
    encrypted_seed  TEXT,                  -- Base64-encoded encrypted blob
    owner           TEXT,                  -- Owner wallet address
    created_at      INTEGER,               -- Unix timestamp (ms)
    last_used       INTEGER DEFAULT 0,     -- Unix timestamp (ms)
    key_hash        TEXT UNIQUE,           -- Keccak256 hash for lookups
    type            TEXT DEFAULT 'l2s'     -- Storage type
);
```

### Database Location

```
project_root/
└── data/
    └── l2s.db       -- SQLite database file
```

---

## Data Flow

### Registration Flow

```
1. User enters seed phrase in browser
          ↓
2. SDK encrypts with user's password (AES-256-GCM)
   - Generate random salt (16 bytes)
   - Generate random IV (12 bytes)
   - Derive key: PBKDF2(password, salt, 100000 iterations)
   - Encrypt: AES-256-GCM(seed, key, iv)
   - Output: base64(salt + iv + ciphertext)
          ↓
3. SDK generates proxy key ID: priv_secret{random_64_hex_chars}
          ↓
4. SDK computes key hash: keccak256(proxy_key_bytes)
          ↓
5. SDK sends to API: POST /api/sdk/register
   {
     proxyKeyId: "priv_secret...",
     keyHash: "0x...",
     encryptedSeed: "base64...",
     label: "My Vault",
     ownerAddress: "0x..."
   }
          ↓
6. Server stores in SQLite:
   INSERT INTO sdk_vaults (id, proxy_key_id, key_hash, encrypted_seed, ...)
          ↓
7. Server returns success, SDK returns proxyKeyId to user
```

### Authentication Flow

```
1. User provides proxy key ID + password
          ↓
2. SDK computes key hash: keccak256(proxy_key_bytes)
          ↓
3. SDK sends to API: POST /api/sdk/getSeed
   { keyHash: "0x..." }
          ↓
4. Server queries: SELECT * FROM sdk_vaults WHERE key_hash = ? AND is_active = 1
          ↓
5. Server returns: { encryptedSeed: "base64..." }
          ↓
6. SDK decrypts with password (reverse of encryption)
   - Decode base64
   - Extract salt, iv, ciphertext
   - Derive key: PBKDF2(password, salt)
   - Decrypt: AES-256-GCM-Decrypt(ciphertext, key, iv)
          ↓
7. SDK generates new proxy key ID
          ↓
8. SDK sends rotation: POST /api/sdk/rotate
   { oldKeyHash: "0x...", newKeyHash: "0x..." }
          ↓
9. Server updates: UPDATE sdk_vaults SET key_hash = ? WHERE key_hash = ?
          ↓
10. SDK returns seed phrase + new proxy key to user
```

### Key Rotation

```sql
-- Old key hash is replaced with new key hash
UPDATE sdk_vaults 
SET key_hash = 'new_hash', 
    last_used = current_timestamp_ms 
WHERE key_hash = 'old_hash' 
  AND is_active = 1;
```

The old proxy key immediately becomes invalid. Only the new key works.

### Revocation

```sql
-- Vault is marked inactive (soft delete)
UPDATE sdk_vaults 
SET is_active = 0 
WHERE key_hash = 'key_hash';
```

Revoked vaults cannot be used again, but the data remains for audit purposes.

---

## API Endpoints

All endpoints are under `/api/sdk/[action]`

### POST /api/sdk/register

Register a new encrypted vault.

**Request:**
```json
{
  "proxyKeyId": "priv_secret...",
  "keyHash": "0x...",
  "encryptedSeed": "base64...",
  "label": "My Vault",
  "ownerAddress": "0x...",
  "storageType": "l2s"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "sdk_1703577600000",
    "vaultIndex": -1
  }
}
```

### POST /api/sdk/getSeed

Retrieve encrypted seed for decryption.

**Request:**
```json
{
  "keyHash": "0x..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "encryptedSeed": "base64..."
  }
}
```

### POST /api/sdk/rotate

Rotate key hash (invalidate old, set new).

**Request:**
```json
{
  "oldKeyHash": "0x...",
  "newKeyHash": "0x...",
  "isL2S": true
}
```

**Response:**
```json
{
  "success": true
}
```

### POST /api/sdk/revoke

Permanently revoke a key.

**Request:**
```json
{
  "keyHash": "0x..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "revoked": true
  }
}
```

### GET /api/sdk/vaults?owner=0x...

List all vaults for an owner.

**Response:**
```json
{
  "success": true,
  "data": {
    "vaults": [
      {
        "id": "sdk_1703577600000",
        "label": "My Vault",
        "createdAt": 1703577600000,
        "lastUsed": 1703577700000,
        "isActive": true,
        "type": "l2s"
      }
    ]
  }
}
```

---

## Security Considerations

### What the Server Sees

| Data | Server Access |
|------|---------------|
| Encrypted seed blob | Yes (but cannot decrypt) |
| Key hash | Yes (used for lookups) |
| Owner address | Yes (for listing) |
| Label | Yes (plaintext) |
| Timestamps | Yes |
| Password | No (never sent) |
| Proxy key | No (only hash sent) |
| Decrypted seed | No (never on server) |

### What the Server Cannot Do

- **Decrypt seeds** - No access to password
- **Forge authentications** - Cannot create valid key hashes
- **Determine proxy keys** - Only sees hashes

### What the Server Can Do (Risks)

- **Delete data** - Denial of service
- **Log access patterns** - Privacy concern
- **Refuse to rotate** - Lock users out

### Mitigations

1. **Self-host** - Run your own Pribado instance
2. **Backup keys** - Keep proxy keys in multiple places
3. **Use Sapphire** - For sensitive applications

---

## Self-Hosting

### Database Location

```bash
# Default location
project_root/data/l2s.db

# Custom location (set in code)
const DB_PATH = path.join(process.cwd(), 'data', 'l2s.db');
```

### Backup

```bash
# Backup the SQLite database
cp data/l2s.db backups/l2s_$(date +%Y%m%d).db

# Or use SQLite backup command
sqlite3 data/l2s.db ".backup 'backups/l2s_backup.db'"
```

### Migration

The schema auto-migrates when the server starts:

```typescript
// Creates tables if they don't exist
db.exec(`
    CREATE TABLE IF NOT EXISTS sdk_vaults (...)
`);

// Adds columns if missing
try {
    db.exec('ALTER TABLE l2s_vaults ADD COLUMN last_used INTEGER DEFAULT 0');
} catch (e) {
    // Column already exists
}
```

### Security Hardening

1. **Restrict file permissions:**
   ```bash
   chmod 600 data/l2s.db
   ```

2. **Backup regularly:**
   ```bash
   crontab -e
   0 2 * * * cp /app/data/l2s.db /backups/l2s_$(date +\%Y\%m\%d).db
   ```

3. **Enable HTTPS** - Always use TLS in production

4. **Add API rate limiting** - Prevent brute-force attacks
