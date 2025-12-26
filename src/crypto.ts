/**
 * Pribado Seed Proxy SDK
 * 
 * Cryptographic utilities for client-side encryption
 * 
 * @author Ralph Lawrence Pecayo
 */

import { ethers } from 'ethers';

// ============================================================================
// Seed Phrase Validation
// ============================================================================

/**
 * Validate a BIP39 seed phrase
 */
export function validateSeedPhrase(phrase: string): boolean {
    if (!phrase || typeof phrase !== 'string') return false;

    const words = phrase.trim().toLowerCase().split(/\s+/);

    // Must be 12 or 24 words
    if (words.length !== 12 && words.length !== 24) return false;

    // All words must be alphabetic
    return words.every(word => /^[a-z]+$/.test(word));
}

/**
 * Validate an Ethereum private key
 */
export function validatePrivateKey(key: string): boolean {
    if (!key || typeof key !== 'string') return false;

    // Remove 0x prefix if present
    const cleanKey = key.startsWith('0x') ? key.slice(2) : key;

    // Must be 64 hex characters
    return /^[0-9a-fA-F]{64}$/.test(cleanKey);
}

/**
 * Validate an Ethereum address
 */
export function validateAddress(address: string): boolean {
    try {
        return ethers.isAddress(address);
    } catch {
        return false;
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Generate a random proxy key ID
 */
export function generateProxyKeyId(isL2S: boolean = false): string {
    const randomBytes = ethers.randomBytes(32);
    const hex = ethers.hexlify(randomBytes).slice(2);
    return isL2S ? `priv_secret${hex}` : `priv_${hex}`;
}

/**
 * Hash a proxy key ID for storage/lookup
 */
export function hashProxyKey(proxyKeyId: string): string {
    // Parse the key to bytes32
    let keyBytes: string;
    if (proxyKeyId.startsWith('priv_secret')) {
        keyBytes = '0x' + proxyKeyId.slice(11);
    } else if (proxyKeyId.startsWith('priv_')) {
        keyBytes = '0x' + proxyKeyId.slice(5);
    } else {
        keyBytes = proxyKeyId;
    }

    return ethers.keccak256(ethers.solidityPacked(['bytes32'], [keyBytes]));
}

/**
 * Parse a proxy key to bytes32 format
 */
export function parseProxyKey(proxyKeyId: string): string {
    if (proxyKeyId.startsWith('priv_secret')) {
        return '0x' + proxyKeyId.slice(11);
    } else if (proxyKeyId.startsWith('priv_')) {
        return '0x' + proxyKeyId.slice(5);
    }
    return proxyKeyId;
}

// ============================================================================
// Encryption / Decryption (Client-Side)
// ============================================================================

/**
 * Derive an encryption key from password and salt
 */
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt.buffer as ArrayBuffer,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt a seed phrase with password (client-side, before sending to server)
 * 
 * @param seedPhrase - The seed phrase to encrypt
 * @param password - User's password
 * @returns Encrypted blob (base64 encoded)
 */
export async function encryptSeedPhrase(seedPhrase: string, password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(seedPhrase);

    // Generate random salt and IV
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Derive encryption key
    const key = await deriveKey(password, salt);

    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
    );

    // Combine salt + iv + ciphertext
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);

    // Return as base64
    return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypt an encrypted seed phrase (client-side)
 * 
 * @param encryptedBlob - Base64 encoded encrypted data
 * @param password - User's password
 * @returns Decrypted seed phrase
 */
export async function decryptSeedPhrase(encryptedBlob: string, password: string): Promise<string> {
    // Decode base64
    const combined = Uint8Array.from(atob(encryptedBlob), c => c.charCodeAt(0));

    // Extract salt, iv, and ciphertext
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ciphertext = combined.slice(28);

    // Derive key
    const key = await deriveKey(password, salt);

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

// ============================================================================
// Seed Words Encoding (for Sapphire contract)
// ============================================================================

/**
 * Convert a word to bytes32
 */
export function wordToBytes32(word: string): string {
    const bytes = ethers.toUtf8Bytes(word);
    const padded = ethers.zeroPadBytes(bytes, 32);
    return padded;
}

/**
 * Convert bytes32 to word
 */
export function bytes32ToWord(bytes32: string): string {
    try {
        // Remove trailing zeros
        const hex = bytes32.replace(/0+$/, '');
        if (hex.length <= 2) return '';
        return ethers.toUtf8String(hex);
    } catch {
        return '';
    }
}

/**
 * Encode a seed phrase into 12 bytes32 words for Sapphire contract
 */
export function encodeSeedWords(seedPhrase: string): { words: string[], count: number } {
    const wordList = seedPhrase.trim().split(/\s+/);
    const words: string[] = [];

    for (let i = 0; i < 12; i++) {
        if (i < wordList.length) {
            words.push(wordToBytes32(wordList[i]));
        } else {
            words.push(ethers.zeroPadBytes('0x', 32));
        }
    }

    return { words, count: wordList.length };
}

/**
 * Decode bytes32 words back to seed phrase
 */
export function decodeSeedWords(words: string[], count: number): string {
    const wordList: string[] = [];

    for (let i = 0; i < count; i++) {
        const word = bytes32ToWord(words[i]);
        if (word) wordList.push(word);
    }

    return wordList.join(' ');
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Hash owner address to bytes32
 */
export function hashOwner(address: string): string {
    return ethers.keccak256(ethers.solidityPacked(['address'], [address]));
}

/**
 * Convert label string to bytes32
 */
export function labelToBytes32(label: string): string {
    const bytes = ethers.toUtf8Bytes(label.slice(0, 31)); // Max 31 chars
    return ethers.zeroPadBytes(bytes, 32);
}

/**
 * Convert bytes32 to label string
 */
export function bytes32ToLabel(bytes32: string): string {
    try {
        const hex = bytes32.replace(/0+$/, '');
        if (hex.length <= 2) return '';
        return ethers.toUtf8String(hex);
    } catch {
        return '';
    }
}

/**
 * Derive wallet address from seed phrase
 */
export function deriveAddress(seedPhrase: string): string {
    try {
        const wallet = ethers.Wallet.fromPhrase(seedPhrase);
        return wallet.address;
    } catch {
        throw new Error('Invalid seed phrase');
    }
}
