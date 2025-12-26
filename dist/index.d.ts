/**
 * Pribado Seed Proxy SDK
 *
 * Types and Interfaces for Oasis Sapphire integration
 *
 * @author Ralph Lawrence Pecayo
 */
/** Oasis Sapphire Mainnet Chain ID */
declare const SAPPHIRE_MAINNET_CHAIN_ID = 23294;
/** KeyBridgeV9 Contract Address on Sapphire Mainnet - Supports Seed Phrases AND Private Keys */
declare const CONTRACT_ADDRESS = "0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0";
/** Key Types */
declare const KEY_TYPE_SEED = 0;
declare const KEY_TYPE_PRIVATE_KEY = 1;
type KeyType = 'seed' | 'privateKey';
interface SeedProxyConfig {
    /** Base URL of the Seed Proxy API (e.g., 'https://your-instance.com' or 'http://localhost:3000') */
    baseUrl: string;
    /** API key for authentication (optional for some endpoints) */
    apiKey?: string;
    /** Storage type preference: 'sapphire' (on-chain TEE) or 'l2s' (off-chain encrypted) */
    defaultStorage?: 'sapphire' | 'l2s';
    /** Request timeout in milliseconds (default: 30000) */
    timeout?: number;
}
interface VaultInfo {
    /** Unique vault identifier */
    id: string;
    /** Vault index (positive for Sapphire, negative for L2S) */
    index: number;
    /** Human-readable label */
    label: string;
    /** Unix timestamp (ms) when created */
    createdAt: number;
    /** Unix timestamp (ms) when last used */
    lastUsed: number;
    /** Number of message signatures */
    signatureCount: number;
    /** Number of logins */
    loginCount: number;
    /** Whether vault is active */
    isActive: boolean;
    /** Storage type */
    type: 'sapphire' | 'l2s';
    /** Key type: 'seed' for seed phrase, 'privateKey' for Ethereum private key */
    keyType?: KeyType;
}
interface RegisterVaultParams {
    /**
     * The secret to encrypt - can be either:
     * - Seed phrase (12 or 24 words)
     * - Private key (0x + 64 hex chars)
     */
    secret: string;
    /** @deprecated Use 'secret' instead. Alias for seed phrase. */
    seedPhrase?: string;
    /** Password for encryption */
    password: string;
    /** Human-readable label for the vault */
    label?: string;
    /** Owner's wallet address */
    ownerAddress: string;
    /** Storage type: 'sapphire' or 'l2s' */
    storageType?: 'sapphire' | 'l2s';
    /**
     * Key type: auto-detected if not provided
     * - 'seed' for seed phrase
     * - 'privateKey' for Ethereum private key
     */
    keyType?: KeyType;
}
interface RegisterVaultResult {
    /** Success status */
    success: boolean;
    /** The proxy key ID (priv_xxx or priv_secret_xxx) */
    proxyKeyId: string;
    /** Vault index */
    vaultIndex?: number;
    /** Transaction hash (for Sapphire only) */
    txHash?: string;
    /** Error message if failed */
    error?: string;
}
interface AuthenticateParams {
    /** The proxy key ID */
    proxyKeyId: string;
    /** Password for decryption */
    password: string;
}
interface AuthenticateResult {
    /** Success status */
    success: boolean;
    /** The recovered seed phrase (only on success) */
    seedPhrase?: string;
    /** New rotated proxy key ID */
    newProxyKeyId?: string;
    /** Error message if failed */
    error?: string;
}
interface SignMessageParams {
    /** The proxy key ID */
    proxyKeyId: string;
    /** Password for authentication */
    password: string;
    /** Message to sign (string or hex) */
    message: string;
}
interface SignMessageResult {
    /** Success status */
    success: boolean;
    /** The signature (0x-prefixed hex) */
    signature?: string;
    /** Signature components */
    v?: number;
    r?: string;
    s?: string;
    /** Error message if failed */
    error?: string;
}
interface SignTransactionParams {
    /** The proxy key ID */
    proxyKeyId: string;
    /** Password for authentication */
    password: string;
    /** Transaction object */
    transaction: {
        to: string;
        value?: string;
        data?: string;
        nonce?: number;
        gasLimit?: string;
        gasPrice?: string;
        maxFeePerGas?: string;
        maxPriorityFeePerGas?: string;
        chainId?: number;
    };
}
interface SignTransactionResult {
    /** Success status */
    success: boolean;
    /** Signed transaction (serialized, ready to broadcast) */
    signedTransaction?: string;
    /** Signature */
    signature?: string;
    /** Error message if failed */
    error?: string;
}
interface VerifyKeyParams {
    /** The proxy key ID to verify */
    proxyKeyId: string;
}
interface VerifyKeyResult {
    /** Whether the key exists */
    exists: boolean;
    /** Whether the key is valid */
    valid: boolean;
    /** Whether the key is active (not revoked) */
    isActive: boolean;
    /** Vault index */
    vaultIndex?: number;
    /** Key type */
    type?: 'sapphire' | 'l2s';
    /** Error message if any */
    error?: string;
}
interface RotateKeyParams {
    /** Current proxy key ID */
    proxyKeyId: string;
    /** Password for authentication */
    password: string;
}
interface RotateKeyResult {
    /** Success status */
    success: boolean;
    /** New proxy key ID */
    newProxyKeyId?: string;
    /** Error message if failed */
    error?: string;
}
interface RevokeKeyParams {
    /** The proxy key ID to revoke */
    proxyKeyId: string;
    /** Password for authentication */
    password: string;
}
interface RevokeKeyResult {
    /** Success status */
    success: boolean;
    /** Transaction hash (for Sapphire) */
    txHash?: string;
    /** Error message if failed */
    error?: string;
}
interface ApiResponse<T = unknown> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}
declare enum SeedProxyErrorCode {
    INVALID_CONFIG = "INVALID_CONFIG",
    MISSING_API_KEY = "MISSING_API_KEY",
    INVALID_PASSWORD = "INVALID_PASSWORD",
    INVALID_KEY = "INVALID_KEY",
    KEY_NOT_FOUND = "KEY_NOT_FOUND",
    KEY_INACTIVE = "KEY_INACTIVE",
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED",
    INVALID_SEED_PHRASE = "INVALID_SEED_PHRASE",
    INVALID_PRIVATE_KEY = "INVALID_PRIVATE_KEY",
    INVALID_ADDRESS = "INVALID_ADDRESS",
    INVALID_TRANSACTION = "INVALID_TRANSACTION",
    REGISTRATION_FAILED = "REGISTRATION_FAILED",
    SIGNING_FAILED = "SIGNING_FAILED",
    ROTATION_FAILED = "ROTATION_FAILED",
    REVOCATION_FAILED = "REVOCATION_FAILED",
    NETWORK_ERROR = "NETWORK_ERROR",
    TIMEOUT = "TIMEOUT",
    RATE_LIMITED = "RATE_LIMITED",
    GAS_LIMIT_EXCEEDED = "GAS_LIMIT_EXCEEDED"
}
declare class SeedProxyError extends Error {
    code: SeedProxyErrorCode;
    cause?: Error | undefined;
    constructor(message: string, code: SeedProxyErrorCode, cause?: Error | undefined);
}

/**
 * Pribado Seed Proxy SDK
 *
 * Main Client Class - HTTP-based integration for secure seed management
 *
 * @author Ralph Lawrence Pecayo
 * @license MIT
 */

declare class SeedProxyClient {
    private config;
    private abortController;
    constructor(config: SeedProxyConfig);
    /**
     * Register a new seed phrase vault
     *
     * The seed phrase is encrypted client-side before being sent to the server.
     *
     * @example
     * ```typescript
     * const result = await client.registerVault({
     *   seedPhrase: 'word1 word2 ... word12',
     *   password: 'secure-password',
     *   label: 'My Main Wallet',
     *   ownerAddress: '0x...',
     *   storageType: 'l2s' // or 'sapphire'
     * });
     *
     * console.log('Proxy Key:', result.proxyKeyId);
     * // Save this key securely - it's needed for authentication
     * ```
     */
    registerVault(params: RegisterVaultParams): Promise<RegisterVaultResult>;
    /**
     * Authenticate using a proxy key to recover the seed phrase
     *
     * This also rotates the key for security (one-time use).
     *
     * @example
     * ```typescript
     * const result = await client.authenticate({
     *   proxyKeyId: 'priv_abc123...',
     *   password: 'your-password'
     * });
     *
     * if (result.success) {
     *   console.log('Seed:', result.seedPhrase);
     *   console.log('New Key:', result.newProxyKeyId);
     *   // Store the new key for next login
     * }
     * ```
     */
    authenticate(params: AuthenticateParams): Promise<AuthenticateResult>;
    /**
     * Verify if a proxy key exists and is active
     *
     * @example
     * ```typescript
     * const result = await client.verifyKey({ proxyKeyId: 'priv_abc123...' });
     *
     * if (result.valid && result.isActive) {
     *   console.log('Key is valid and can be used');
     * }
     * ```
     */
    verifyKey(params: VerifyKeyParams): Promise<VerifyKeyResult>;
    /**
     * Rotate a proxy key (invalidates old key, generates new one)
     *
     * @example
     * ```typescript
     * const result = await client.rotateKey({
     *   proxyKeyId: 'priv_old...',
     *   password: 'your-password'
     * });
     *
     * console.log('New key:', result.newProxyKeyId);
     * ```
     */
    rotateKey(params: RotateKeyParams): Promise<RotateKeyResult>;
    /**
     * Permanently revoke a proxy key
     *
     * @example
     * ```typescript
     * const result = await client.revokeKey({
     *   proxyKeyId: 'priv_abc123...',
     *   password: 'your-password'
     * });
     * ```
     */
    revokeKey(params: RevokeKeyParams): Promise<RevokeKeyResult>;
    /**
     * List all vaults for an owner address
     *
     * @example
     * ```typescript
     * const vaults = await client.listVaults('0x...');
     *
     * for (const vault of vaults) {
     *   console.log(vault.label, vault.type, vault.isActive);
     * }
     * ```
     */
    listVaults(ownerAddress: string): Promise<VaultInfo[]>;
    /**
     * Sign a message using the seed stored in a vault
     *
     * This decrypts the seed temporarily to sign, then clears it from memory.
     *
     * @example
     * ```typescript
     * const result = await client.signMessage({
     *   proxyKeyId: 'priv_abc123...',
     *   password: 'your-password',
     *   message: 'Hello, World!'
     * });
     *
     * console.log('Signature:', result.signature);
     * ```
     */
    signMessage(params: SignMessageParams): Promise<SignMessageResult>;
    /**
     * Sign a transaction using the seed stored in a vault
     *
     * @example
     * ```typescript
     * const result = await client.signTransaction({
     *   proxyKeyId: 'priv_abc123...',
     *   password: 'your-password',
     *   transaction: {
     *     to: '0x...',
     *     value: '1000000000000000000', // 1 ETH in wei
     *     chainId: 1
     *   }
     * });
     *
     * // Broadcast the signed transaction
     * const txHash = await provider.sendTransaction(result.signedTransaction);
     * ```
     */
    signTransaction(params: SignTransactionParams): Promise<SignTransactionResult>;
    /**
     * Get the configured base URL
     */
    getBaseUrl(): string;
    /**
     * Get the default storage type
     */
    getDefaultStorage(): 'sapphire' | 'l2s';
    /**
     * Cancel any pending requests
     */
    cancelPendingRequests(): void;
    private request;
}
/**
 * Create a new Seed Proxy client instance
 *
 * @example
 * ```typescript
 * import { createSeedProxyClient } from '@pribado/seed-proxy-sdk';
 *
 * const client = createSeedProxyClient({
 *   baseUrl: 'https://your-pribado-instance.com',
 *   defaultStorage: 'l2s'
 * });
 * ```
 */
declare function createSeedProxyClient(config: SeedProxyConfig): SeedProxyClient;

/**
 * Pribado Seed Proxy SDK
 *
 * Cryptographic utilities for client-side encryption
 *
 * @author Ralph Lawrence Pecayo
 */
/**
 * Validate a BIP39 seed phrase
 */
declare function validateSeedPhrase(phrase: string): boolean;
/**
 * Validate an Ethereum private key
 */
declare function validatePrivateKey(key: string): boolean;
/**
 * Validate an Ethereum address
 */
declare function validateAddress(address: string): boolean;
/**
 * Generate a random proxy key ID
 */
declare function generateProxyKeyId(isL2S?: boolean): string;
/**
 * Hash a proxy key ID for storage/lookup
 */
declare function hashProxyKey(proxyKeyId: string): string;
/**
 * Parse a proxy key to bytes32 format
 */
declare function parseProxyKey(proxyKeyId: string): string;
/**
 * Encrypt a seed phrase with password (client-side, before sending to server)
 *
 * @param seedPhrase - The seed phrase to encrypt
 * @param password - User's password
 * @returns Encrypted blob (base64 encoded)
 */
declare function encryptSeedPhrase(seedPhrase: string, password: string): Promise<string>;
/**
 * Decrypt an encrypted seed phrase (client-side)
 *
 * @param encryptedBlob - Base64 encoded encrypted data
 * @param password - User's password
 * @returns Decrypted seed phrase
 */
declare function decryptSeedPhrase(encryptedBlob: string, password: string): Promise<string>;
/**
 * Encode a seed phrase into 12 bytes32 words for Sapphire contract
 */
declare function encodeSeedWords(seedPhrase: string): {
    words: string[];
    count: number;
};
/**
 * Decode bytes32 words back to seed phrase
 */
declare function decodeSeedWords(words: string[], count: number): string;
/**
 * Hash owner address to bytes32
 */
declare function hashOwner(address: string): string;
/**
 * Convert label string to bytes32
 */
declare function labelToBytes32(label: string): string;
/**
 * Convert bytes32 to label string
 */
declare function bytes32ToLabel(bytes32: string): string;
/**
 * Derive wallet address from seed phrase
 */
declare function deriveAddress(seedPhrase: string): string;

/**
 * Pribado Seed Proxy SDK
 *
 * Secure encrypted endpoints for Web3 wallets
 *
 * @packageDocumentation
 * @author Ralph Lawrence Pecayo
 * @license MIT
 */

declare const VERSION = "2.0.0";

export { type ApiResponse, type AuthenticateParams, type AuthenticateResult, CONTRACT_ADDRESS, KEY_TYPE_PRIVATE_KEY, KEY_TYPE_SEED, type KeyType, type RegisterVaultParams, type RegisterVaultResult, type RevokeKeyParams, type RevokeKeyResult, type RotateKeyParams, type RotateKeyResult, SAPPHIRE_MAINNET_CHAIN_ID, SeedProxyClient, type SeedProxyConfig, SeedProxyError, SeedProxyErrorCode, type SignMessageParams, type SignMessageResult, type SignTransactionParams, type SignTransactionResult, VERSION, type VaultInfo, type VerifyKeyParams, type VerifyKeyResult, bytes32ToLabel, createSeedProxyClient, decodeSeedWords, decryptSeedPhrase, createSeedProxyClient as default, deriveAddress, encodeSeedWords, encryptSeedPhrase, generateProxyKeyId, hashOwner, hashProxyKey, labelToBytes32, parseProxyKey, validateAddress, validatePrivateKey, validateSeedPhrase };
