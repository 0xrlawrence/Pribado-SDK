# Smart Contract Reference

This document describes the KeyBridgeV9 smart contract deployed on Oasis Sapphire.

---

## Table of Contents

1. [Overview](#overview)
2. [Deployment](#deployment)
3. [Data Structures](#data-structures)
4. [Contract Functions](#contract-functions)
5. [Events](#events)
6. [Error Codes](#error-codes)
7. [Full Source Code](#full-source-code)

---

## Overview

**KeyBridgeV9** is a Solidity smart contract deployed on Oasis Sapphire that provides:

- Encrypted **seed phrase** and **private key** storage using XOR encryption with position-based keys
- Key type differentiation (seed phrase vs private key)
- Key rotation for security
- Vault management (create, verify, deactivate)
- Owner-based vault listing

**V9 Features:**
- Support for both seed phrases (12/24 words) and private keys (0x...)
- New `keyType` field (0 = seed, 1 = privateKey)
- Same heavy encryption for both types

The contract runs on Oasis Sapphire's Trusted Execution Environment (TEE), which means:
- Contract state is encrypted at rest
- Computations happen inside secure hardware enclaves
- Data is protected from node operators

---

## Deployment

| Network | Contract Address | Version |
|---------|------------------|---------|
| Sapphire Mainnet | [`0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0`](https://explorer.oasis.io/mainnet/sapphire/address/0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0) | V9 |
| Sapphire Mainnet (Legacy) | `0x9B4aA4B40995bD93256E26706A12535851C4FD95` | V8 |

**View Live Contract:** [Oasis Explorer](https://explorer.oasis.io/mainnet/sapphire/address/0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0)

**Chain ID:** `23294`

**RPC URL:** `https://sapphire.oasis.io`

---

## Data Structures

### Vault Struct

```solidity
struct Vault {
    bytes32[12] encryptedWords;  // 12 words for seed, or encrypted private key chunks
    uint8 wordCount;              // Number of encrypted chunks
    uint8 keyType;                // 0 = seed phrase, 1 = private key (NEW in V9)
    bytes32 encryptionKey;        // Per-vault encryption key
    bytes32 currentKeyHash;       // Hash of current proxy key
    bytes32 label;                // Human-readable label
    bytes32 ownerHash;            // Keccak256 of owner address
    uint64 createdAt;             // Unix timestamp
    uint64 lastUsed;              // Unix timestamp of last use
    uint32 signatureCount;        // Number of signatures made
    uint32 loginCount;            // Number of logins (rotations)
    bool isActive;                // Whether vault is active
}
```

### Key Type Constants

```solidity
uint8 public constant KEY_TYPE_SEED = 0;        // Seed phrase (12/24 words)
uint8 public constant KEY_TYPE_PRIVATE_KEY = 1; // Ethereum private key (0x...)
```

### Storage Layout

```solidity
mapping(bytes32 => uint256) private keyHashToVault;      // Key hash -> vault index
Vault[] private allVaults;                                // All vaults
mapping(bytes32 => uint256[]) private ownerVaultIndices;  // Owner -> vault indices
```

---

## Contract Functions

### registerVault

Register a new vault with encrypted seed words.

```solidity
function registerVault(
    bytes32 keyHash,
    bytes32[12] calldata seedWords,
    uint8 wordCount,
    bytes32 label,
    bytes32 ownerHash
) external returns (uint256 vaultIndex)
```

**Parameters:**
- `keyHash` - Keccak256 hash of the proxy key
- `seedWords` - Array of 12 bytes32-encoded seed words
- `wordCount` - Number of actual words (12 or 24)
- `label` - Human-readable label (bytes32 encoded)
- `ownerHash` - Keccak256 hash of owner's address

**Returns:** `vaultIndex` - The index of the newly created vault

**Encryption:**
Each word is XOR-encrypted with a position-based key derived from:
```solidity
bytes32 wordKey = keccak256(abi.encodePacked(encryptionKey, index));
encryptedWord = seedWord ^ wordKey;
```

---

### getSeedWords

Retrieve decrypted seed words using the proxy key.

```solidity
function getSeedWords(bytes32 privKey) external view returns (
    bytes32[12] memory words,
    uint8 count
)
```

**Parameters:**
- `privKey` - The raw proxy key (will be hashed to verify)

**Returns:**
- `words` - Array of 12 decrypted seed words (as bytes32)
- `count` - Number of actual words

**Security:** The proxy key is verified against the stored hash before decryption.

---

### rotateKey

Rotate the proxy key (invalidate old, set new).

```solidity
function rotateKey(
    bytes32 oldPrivKey, 
    bytes32 newKeyHash
) external returns (uint256 vaultIndex)
```

**Parameters:**
- `oldPrivKey` - The current proxy key (raw, will be verified)
- `newKeyHash` - Keccak256 hash of the new proxy key

**Returns:** `vaultIndex` - The vault index

**Side Effects:**
- Old key hash is invalidated
- New key hash is stored
- `lastUsed` timestamp updated
- `loginCount` incremented

---

### verifyKey

Verify if a proxy key is valid and active.

```solidity
function verifyKey(bytes32 privKey) external view returns (
    bool valid,
    uint256 vaultIndex,
    bool isActive
)
```

**Parameters:**
- `privKey` - The proxy key to verify

**Returns:**
- `valid` - Whether the key matches the stored hash
- `vaultIndex` - The vault index (0 if not found)
- `isActive` - Whether the vault is active

---

### deactivateVault

Permanently deactivate a vault (revoke access).

```solidity
function deactivateVault(bytes32 privKey) external
```

**Parameters:**
- `privKey` - The proxy key for the vault

**Side Effects:**
- Vault marked as `isActive = false`
- Key hash mapping deleted
- Vault can never be used again

---

### getVaultInfo

Get metadata about a vault by index.

```solidity
function getVaultInfo(uint256 vaultIndex) external view returns (
    bytes32 label,
    uint64 createdAt,
    uint64 lastUsed,
    uint32 signatureCount,
    uint32 loginCount,
    bool isActive
)
```

---

### getOwnerVaults

Get all vault indices for an owner.

```solidity
function getOwnerVaults(bytes32 ownerHash) external view returns (uint256[] memory)
```

---

### getMyVaultsData

Get aggregated data for all vaults owned by an address.

```solidity
function getMyVaultsData(bytes32 ownerHash) external view returns (
    uint256[] memory indices,
    bytes32[] memory labels,
    uint32[] memory sigCounts,
    uint32[] memory loginCounts,
    bool[] memory actives
)
```

---

## Events

```solidity
event VaultCreated(bytes32 indexed ownerHash, uint256 vaultIndex, uint64 timestamp);
event KeyRotated(uint256 indexed vaultIndex, uint64 timestamp);
event VaultDeactivated(uint256 indexed vaultIndex);
```

---

## Error Codes

| Error | Description |
|-------|-------------|
| `VaultNotFound()` | Vault index does not exist |
| `VaultNotActive()` | Vault has been deactivated |
| `InvalidKey()` | Proxy key does not match stored hash |
| `EmptySeed()` | No seed words provided |
| `KeyHashAlreadyUsed()` | Key hash already registered |
| `TooManyWords()` | Word count is 0 or > 12 |

---

## Full Source Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title KeyBridgeV8
 * @notice Privacy-first Key Proxy - Fixed return type for Sapphire
 * 
 * Stores seed as 12 bytes32 words to avoid string return issues
 */
contract KeyBridgeV8 {
    
    struct Vault {
        bytes32[12] encryptedWords;  // 12 words max (standard BIP39)
        uint8 wordCount;              // Actual word count
        bytes32 encryptionKey;
        bytes32 currentKeyHash;
        bytes32 label;
        bytes32 ownerHash;
        uint64 createdAt;
        uint64 lastUsed;
        uint32 signatureCount;
        uint32 loginCount;
        bool isActive;
    }
    
    mapping(bytes32 => uint256) private keyHashToVault;
    Vault[] private allVaults;
    mapping(bytes32 => uint256[]) private ownerVaultIndices;
    
    uint8 public constant VERSION = 8;
    
    event VaultCreated(bytes32 indexed ownerHash, uint256 vaultIndex, uint64 timestamp);
    event KeyRotated(uint256 indexed vaultIndex, uint64 timestamp);
    event VaultDeactivated(uint256 indexed vaultIndex);
    
    error VaultNotFound();
    error VaultNotActive();
    error InvalidKey();
    error EmptySeed();
    error KeyHashAlreadyUsed();
    error TooManyWords();

    constructor() {
        allVaults.push(); // Index 0 is reserved/invalid
    }

    function _xorBytes32(bytes32 data, bytes32 key) private pure returns (bytes32) {
        return data ^ key;
    }

    function _getWordKey(bytes32 baseKey, uint8 index) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(baseKey, index));
    }

    /**
     * @notice Register vault - encrypts each word with position-based key
     */
    function registerVault(
        bytes32 keyHash,
        bytes32[12] calldata seedWords,
        uint8 wordCount,
        bytes32 label,
        bytes32 ownerHash
    ) external returns (uint256 vaultIndex) {
        if (wordCount == 0 || wordCount > 12) revert TooManyWords();
        if (keyHashToVault[keyHash] != 0) revert KeyHashAlreadyUsed();
        
        vaultIndex = allVaults.length;
        
        bytes32 encKey = keccak256(abi.encodePacked(
            block.timestamp, ownerHash, vaultIndex, keyHash
        ));
        
        bytes32[12] memory encryptedWords;
        for (uint8 i = 0; i < wordCount; i++) {
            bytes32 wordKey = _getWordKey(encKey, i);
            encryptedWords[i] = _xorBytes32(seedWords[i], wordKey);
        }
        
        allVaults.push(Vault({
            encryptedWords: encryptedWords,
            wordCount: wordCount,
            encryptionKey: encKey,
            currentKeyHash: keyHash,
            label: label,
            ownerHash: ownerHash,
            createdAt: uint64(block.timestamp),
            lastUsed: uint64(block.timestamp),
            signatureCount: 0,
            loginCount: 0,
            isActive: true
        }));
        
        keyHashToVault[keyHash] = vaultIndex;
        ownerVaultIndices[ownerHash].push(vaultIndex);
        
        emit VaultCreated(ownerHash, vaultIndex, uint64(block.timestamp));
        return vaultIndex;
    }

    /**
     * @notice Get decrypted seed words - uses position-based decryption
     */
    function getSeedWords(bytes32 privKey) external view returns (
        bytes32[12] memory words,
        uint8 count
    ) {
        bytes32 keyHash = keccak256(abi.encodePacked(privKey));
        uint256 vaultIndex = keyHashToVault[keyHash];
        
        if (vaultIndex == 0) revert InvalidKey();
        
        Vault storage v = allVaults[vaultIndex];
        if (!v.isActive) revert VaultNotActive();
        if (v.currentKeyHash != keyHash) revert InvalidKey();
        
        for (uint8 i = 0; i < v.wordCount; i++) {
            bytes32 wordKey = _getWordKey(v.encryptionKey, i);
            words[i] = _xorBytes32(v.encryptedWords[i], wordKey);
        }
        count = v.wordCount;
    }

    function rotateKey(
        bytes32 oldPrivKey, 
        bytes32 newKeyHash
    ) external returns (uint256 vaultIndex) {
        bytes32 oldKeyHash = keccak256(abi.encodePacked(oldPrivKey));
        vaultIndex = keyHashToVault[oldKeyHash];
        
        if (vaultIndex == 0) revert InvalidKey();
        if (keyHashToVault[newKeyHash] != 0) revert KeyHashAlreadyUsed();
        
        Vault storage v = allVaults[vaultIndex];
        if (!v.isActive) revert VaultNotActive();
        if (v.currentKeyHash != oldKeyHash) revert InvalidKey();
        
        delete keyHashToVault[oldKeyHash];
        v.currentKeyHash = newKeyHash;
        keyHashToVault[newKeyHash] = vaultIndex;
        v.lastUsed = uint64(block.timestamp);
        v.loginCount++;
        
        emit KeyRotated(vaultIndex, uint64(block.timestamp));
    }

    function verifyKey(bytes32 privKey) external view returns (
        bool valid, 
        uint256 vaultIndex, 
        bool isActive
    ) {
        bytes32 keyHash = keccak256(abi.encodePacked(privKey));
        vaultIndex = keyHashToVault[keyHash];
        
        if (vaultIndex == 0) return (false, 0, false);
        
        Vault storage v = allVaults[vaultIndex];
        return (v.currentKeyHash == keyHash, vaultIndex, v.isActive);
    }

    function deactivateVault(bytes32 privKey) external {
        bytes32 keyHash = keccak256(abi.encodePacked(privKey));
        uint256 vaultIndex = keyHashToVault[keyHash];
        
        if (vaultIndex == 0) revert InvalidKey();
        
        Vault storage v = allVaults[vaultIndex];
        if (v.currentKeyHash != keyHash) revert InvalidKey();
        
        v.isActive = false;
        delete keyHashToVault[keyHash];
        
        emit VaultDeactivated(vaultIndex);
    }

    function getVaultInfo(uint256 vaultIndex) external view returns (
        bytes32 label,
        uint64 createdAt,
        uint64 lastUsed,
        uint32 signatureCount,
        uint32 loginCount,
        bool isActive
    ) {
        if (vaultIndex == 0 || vaultIndex >= allVaults.length) revert VaultNotFound();
        Vault storage v = allVaults[vaultIndex];
        return (v.label, v.createdAt, v.lastUsed, v.signatureCount, v.loginCount, v.isActive);
    }

    function getOwnerVaults(bytes32 ownerHash) external view returns (uint256[] memory) {
        return ownerVaultIndices[ownerHash];
    }

    function getMyVaultsData(bytes32 ownerHash) external view returns (
        uint256[] memory indices,
        bytes32[] memory labels,
        uint32[] memory sigCounts,
        uint32[] memory loginCounts,
        bool[] memory actives
    ) {
        uint256[] storage myIndices = ownerVaultIndices[ownerHash];
        uint256 len = myIndices.length;
        
        indices = new uint256[](len);
        labels = new bytes32[](len);
        sigCounts = new uint32[](len);
        loginCounts = new uint32[](len);
        actives = new bool[](len);
        
        for (uint256 i = 0; i < len; i++) {
            Vault storage v = allVaults[myIndices[i]];
            indices[i] = myIndices[i];
            labels[i] = v.label;
            sigCounts[i] = v.signatureCount;
            loginCounts[i] = v.loginCount;
            actives[i] = v.isActive;
        }
    }
}
```

---

## ABI (For SDK Integration)

```json
[
  "function registerVault(bytes32 keyHash, bytes32[12] seedWords, uint8 wordCount, bytes32 label, bytes32 ownerHash) returns (uint256 vaultIndex)",
  "function verifyKey(bytes32 privKey) view returns (bool valid, uint256 vaultIndex, bool isActive)",
  "function rotateKey(bytes32 oldPrivKey, bytes32 newKeyHash) returns (uint256 vaultIndex)",
  "function deactivateVault(bytes32 privKey)",
  "function getSeedWords(bytes32 privKey) view returns (bytes32[12] words, uint8 count)",
  "function getVaultInfo(uint256 vaultIndex) view returns (bytes32 label, uint64 createdAt, uint64 lastUsed, uint32 signatureCount, uint32 loginCount, bool isActive)",
  "function getOwnerVaults(bytes32 ownerHash) view returns (uint256[])",
  "function getMyVaultsData(bytes32 ownerHash) view returns (uint256[] indices, bytes32[] labels, uint32[] sigCounts, uint32[] loginCounts, bool[] actives)",
  "event VaultCreated(bytes32 indexed ownerHash, uint256 vaultIndex, uint64 timestamp)",
  "event KeyRotated(uint256 indexed vaultIndex, uint64 timestamp)",
  "event VaultDeactivated(uint256 indexed vaultIndex)"
]
```
