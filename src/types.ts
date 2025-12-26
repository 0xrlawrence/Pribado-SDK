/**
 * Pribado Seed Proxy SDK
 * 
 * Types and Interfaces for Oasis Sapphire integration
 * 
 * @author Ralph Lawrence Pecayo
 */

// ============================================================================
// Oasis Sapphire Chain ID
// ============================================================================

/** Oasis Sapphire Mainnet Chain ID */
export const SAPPHIRE_MAINNET_CHAIN_ID = 23294;

/** KeyBridgeV9 Contract Address on Sapphire Mainnet - Supports Seed Phrases AND Private Keys */
export const CONTRACT_ADDRESS = '0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0';

/** Key Types */
export const KEY_TYPE_SEED = 0;
export const KEY_TYPE_PRIVATE_KEY = 1;

export type KeyType = 'seed' | 'privateKey';

// ============================================================================
// Configuration Types
// ============================================================================

export interface SeedProxyConfig {
    /** Base URL of the Seed Proxy API (e.g., 'https://your-instance.com' or 'http://localhost:3000') */
    baseUrl: string;

    /** API key for authentication (optional for some endpoints) */
    apiKey?: string;

    /** Storage type preference: 'sapphire' (on-chain TEE) or 'l2s' (off-chain encrypted) */
    defaultStorage?: 'sapphire' | 'l2s';

    /** Request timeout in milliseconds (default: 30000) */
    timeout?: number;
}

// ============================================================================
// Vault Types
// ============================================================================

export interface VaultInfo {
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

export interface RegisterVaultParams {
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

export interface RegisterVaultResult {
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

// ============================================================================
// Authentication Types
// ============================================================================

export interface AuthenticateParams {
    /** The proxy key ID */
    proxyKeyId: string;

    /** Password for decryption */
    password: string;
}

export interface AuthenticateResult {
    /** Success status */
    success: boolean;

    /** The recovered seed phrase (only on success) */
    seedPhrase?: string;

    /** New rotated proxy key ID */
    newProxyKeyId?: string;

    /** Error message if failed */
    error?: string;
}

// ============================================================================
// Signing Types
// ============================================================================

export interface SignMessageParams {
    /** The proxy key ID */
    proxyKeyId: string;

    /** Password for authentication */
    password: string;

    /** Message to sign (string or hex) */
    message: string;
}

export interface SignMessageResult {
    /** Success status */
    success: boolean;

    /** The signature (0x-prefixed hex) */
    signature?: string;

    /** Signature components */
    v?: number;
    r?: string;
    s?: string;

    /** New rotated proxy key ID (CRITICAL: User must save this) */
    newProxyKeyId?: string;

    /** The address that signed the message */
    signerAddress?: string;

    /** Error message if failed */
    error?: string;
}

export interface SignTransactionParams {
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

export interface SignTransactionResult {
    /** Success status */
    success: boolean;

    /** Signed transaction (serialized, ready to broadcast) */
    signedTransaction?: string;

    /** Signature */
    signature?: string;

    /** Error message if failed */
    error?: string;
}

// ============================================================================
// Key Management Types
// ============================================================================

export interface VerifyKeyParams {
    /** The proxy key ID to verify */
    proxyKeyId: string;
}

export interface VerifyKeyResult {
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

export interface RotateKeyParams {
    /** Current proxy key ID */
    proxyKeyId: string;

    /** Password for authentication */
    password: string;
}

export interface RotateKeyResult {
    /** Success status */
    success: boolean;

    /** New proxy key ID */
    newProxyKeyId?: string;

    /** Error message if failed */
    error?: string;
}

export interface RevokeKeyParams {
    /** The proxy key ID to revoke */
    proxyKeyId: string;

    /** Password for authentication */
    password: string;
}

export interface RevokeKeyResult {
    /** Success status */
    success: boolean;

    /** Transaction hash (for Sapphire) */
    txHash?: string;

    /** Error message if failed */
    error?: string;
}

// ============================================================================
// API Response Types
// ============================================================================

export interface ApiResponse<T = unknown> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}

// ============================================================================
// Error Types
// ============================================================================

export enum SeedProxyErrorCode {
    // Configuration errors
    INVALID_CONFIG = 'INVALID_CONFIG',
    MISSING_API_KEY = 'MISSING_API_KEY',

    // Authentication errors
    INVALID_PASSWORD = 'INVALID_PASSWORD',
    INVALID_KEY = 'INVALID_KEY',
    KEY_NOT_FOUND = 'KEY_NOT_FOUND',
    KEY_INACTIVE = 'KEY_INACTIVE',
    AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',

    // Validation errors
    INVALID_SEED_PHRASE = 'INVALID_SEED_PHRASE',
    INVALID_PRIVATE_KEY = 'INVALID_PRIVATE_KEY',
    INVALID_ADDRESS = 'INVALID_ADDRESS',
    INVALID_TRANSACTION = 'INVALID_TRANSACTION',

    // Operation errors
    REGISTRATION_FAILED = 'REGISTRATION_FAILED',
    SIGNING_FAILED = 'SIGNING_FAILED',
    ROTATION_FAILED = 'ROTATION_FAILED',
    REVOCATION_FAILED = 'REVOCATION_FAILED',

    // Network errors
    NETWORK_ERROR = 'NETWORK_ERROR',
    TIMEOUT = 'TIMEOUT',

    // Rate limiting
    RATE_LIMITED = 'RATE_LIMITED',
    GAS_LIMIT_EXCEEDED = 'GAS_LIMIT_EXCEEDED'
}

export class SeedProxyError extends Error {
    constructor(
        message: string,
        public code: SeedProxyErrorCode,
        public cause?: Error
    ) {
        super(message);
        this.name = 'SeedProxyError';
    }
}
