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
        allVaults.push();
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
        
        bytes32 encKey = keccak256(abi.encodePacked(block.timestamp, ownerHash, vaultIndex, keyHash));
        
        bytes32[12] memory encryptedWords;
        for (uint8 i = 0; i < wordCount; i++) {
            // Use position-based key to prevent XOR collisions!
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
        
        // Decrypt with position-based keys
        for (uint8 i = 0; i < v.wordCount; i++) {
            bytes32 wordKey = _getWordKey(v.encryptionKey, i);
            words[i] = _xorBytes32(v.encryptedWords[i], wordKey);
        }
        count = v.wordCount;
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
