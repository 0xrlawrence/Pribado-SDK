// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title KeyBridgeV9
 * @notice Privacy-first Key Proxy - Supports both Seed Phrases AND Private Keys
 * 
 * Key Type:
 *   0 = Seed Phrase (12 words stored in encryptedWords[0..11])
 *   1 = Private Key (1 bytes32 stored in encryptedWords[0])
 * 
 * Both types are pre-encrypted client-side with user's password before storage.
 */
contract KeyBridgeV9 {
    
    // Key types
    uint8 public constant KEY_TYPE_SEED = 0;
    uint8 public constant KEY_TYPE_PRIVATE_KEY = 1;
    
    struct Vault {
        bytes32[12] encryptedWords;   // 12 words for seed, or 1 bytes32 for private key
        uint8 wordCount;               // 12 for seed phrase, 1 for private key
        uint8 keyType;                 // 0 = seed phrase, 1 = private key
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
    
    uint8 public constant VERSION = 9;
    
    event VaultCreated(bytes32 indexed ownerHash, uint256 vaultIndex, uint8 keyType, uint64 timestamp);
    event KeyRotated(uint256 indexed vaultIndex, uint64 timestamp);
    event VaultDeactivated(uint256 indexed vaultIndex);
    
    error VaultNotFound();
    error VaultNotActive();
    error InvalidKey();
    error EmptySeed();
    error KeyHashAlreadyUsed();
    error TooManyWords();
    error InvalidKeyType();

    constructor() {
        // Push empty vault at index 0 (unused - allows index 0 to mean "not found")
        allVaults.push();
    }

    function _xorBytes32(bytes32 data, bytes32 key) private pure returns (bytes32) {
        return data ^ key;
    }

    function _getWordKey(bytes32 baseKey, uint8 index) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(baseKey, index));
    }

    /**
     * @notice Register vault - encrypts each word/key with position-based key
     * @param keyHash Hash of the priv_xxx key for lookup
     * @param seedWords 12 bytes32 words (seed) or 1 bytes32 (private key in [0])
     * @param wordCount Number of words (12 for seed, 1 for private key)
     * @param keyType 0 = seed phrase, 1 = private key
     * @param label Human-readable label for the vault
     * @param ownerHash Hash of owner address for listing
     */
    function registerVault(
        bytes32 keyHash,
        bytes32[12] calldata seedWords,
        uint8 wordCount,
        uint8 keyType,
        bytes32 label,
        bytes32 ownerHash
    ) external returns (uint256 vaultIndex) {
        // Validate
        if (wordCount == 0 || wordCount > 12) revert TooManyWords();
        if (keyType > KEY_TYPE_PRIVATE_KEY) revert InvalidKeyType();
        // Note: Both seed phrases AND private keys use encrypted chunks, so both can have multiple words
        if (keyHashToVault[keyHash] != 0) revert KeyHashAlreadyUsed();
        
        vaultIndex = allVaults.length;
        
        // Generate encryption key from entropy
        bytes32 encKey = keccak256(abi.encodePacked(block.timestamp, ownerHash, vaultIndex, keyHash));
        
        // Encrypt each word with position-based key
        bytes32[12] memory encryptedWords;
        for (uint8 i = 0; i < wordCount; i++) {
            bytes32 wordKey = _getWordKey(encKey, i);
            encryptedWords[i] = _xorBytes32(seedWords[i], wordKey);
        }
        
        allVaults.push(Vault({
            encryptedWords: encryptedWords,
            wordCount: wordCount,
            keyType: keyType,
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
        
        emit VaultCreated(ownerHash, vaultIndex, keyType, uint64(block.timestamp));
        return vaultIndex;
    }

    /**
     * @notice Get decrypted data - returns words AND keyType
     * @param privKey The priv_xxx key
     * @return words Decrypted bytes32 array (12 for seed, 1 for private key)
     * @return count Number of valid words
     * @return keyType 0 = seed phrase, 1 = private key
     */
    function getSeedWords(bytes32 privKey) external view returns (
        bytes32[12] memory words,
        uint8 count,
        uint8 keyType
    ) {
        bytes32 keyHash = keccak256(abi.encodePacked(privKey));
        uint256 vaultIndex = keyHashToVault[keyHash];
        
        if (vaultIndex == 0) revert InvalidKey();
        
        Vault storage v = allVaults[vaultIndex];
        if (!v.isActive) revert VaultNotActive();
        if (v.currentKeyHash != keyHash) revert InvalidKey();
        
        // Decrypt with position-based keys
        for (uint8 i = 0; i < v.wordCount; i++) {
            bytes32 wordKey = _getWordKey(v.encryptionKey, i);
            words[i] = _xorBytes32(v.encryptedWords[i], wordKey);
        }
        count = v.wordCount;
        keyType = v.keyType;
    }

    function rotateKey(bytes32 oldPrivKey, bytes32 newKeyHash) external returns (uint256 vaultIndex) {
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

    function verifyKey(bytes32 privKey) external view returns (bool valid, uint256 vaultIndex, bool isActive) {
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

    /**
     * @notice Get vault info including keyType
     */
    function getVaultInfo(uint256 vaultIndex) external view returns (
        bytes32 label,
        uint64 createdAt,
        uint64 lastUsed,
        uint32 signatureCount,
        uint32 loginCount,
        bool isActive,
        uint8 keyType
    ) {
        if (vaultIndex == 0 || vaultIndex >= allVaults.length) revert VaultNotFound();
        Vault storage v = allVaults[vaultIndex];
        return (v.label, v.createdAt, v.lastUsed, v.signatureCount, v.loginCount, v.isActive, v.keyType);
    }

    function getOwnerVaults(bytes32 ownerHash) external view returns (uint256[] memory) {
        return ownerVaultIndices[ownerHash];
    }

    /**
     * @notice Get all vault data for an owner including keyTypes
     */
    function getMyVaultsData(bytes32 ownerHash) external view returns (
        uint256[] memory indices,
        bytes32[] memory labels,
        uint32[] memory sigCounts,
        uint32[] memory loginCounts,
        bool[] memory actives,
        uint8[] memory keyTypes
    ) {
        uint256[] storage myIndices = ownerVaultIndices[ownerHash];
        uint256 len = myIndices.length;
        
        indices = new uint256[](len);
        labels = new bytes32[](len);
        sigCounts = new uint32[](len);
        loginCounts = new uint32[](len);
        actives = new bool[](len);
        keyTypes = new uint8[](len);
        
        for (uint256 i = 0; i < len; i++) {
            Vault storage v = allVaults[myIndices[i]];
            indices[i] = myIndices[i];
            labels[i] = v.label;
            sigCounts[i] = v.signatureCount;
            loginCounts[i] = v.loginCount;
            actives[i] = v.isActive;
            keyTypes[i] = v.keyType;
        }
    }
}
