/**
 * Pribado Seed Proxy SDK
 * 
 * Secure encrypted endpoints for Web3 wallets
 * 
 * @packageDocumentation
 * @author Ralph Lawrence Pecayo
 * @license MIT
 */

// Main client
export { SeedProxyClient, createSeedProxyClient } from './client';

// Crypto utilities (for advanced users)
export {
    validateSeedPhrase,
    validatePrivateKey,
    validateAddress,
    generateProxyKeyId,
    hashProxyKey,
    parseProxyKey,
    encryptSeedPhrase,
    decryptSeedPhrase,
    encodeSeedWords,
    decodeSeedWords,
    hashOwner,
    labelToBytes32,
    bytes32ToLabel,
    deriveAddress
} from './crypto';

// Types
export type {
    // Configuration
    SeedProxyConfig,

    // Vault
    VaultInfo,
    RegisterVaultParams,
    RegisterVaultResult,

    // Authentication
    AuthenticateParams,
    AuthenticateResult,

    // Signing
    SignMessageParams,
    SignMessageResult,
    SignTransactionParams,
    SignTransactionResult,

    // Key Management
    VerifyKeyParams,
    VerifyKeyResult,
    RotateKeyParams,
    RotateKeyResult,
    RevokeKeyParams,
    RevokeKeyResult,

    // API
    ApiResponse
} from './types';

// Error types and constants
export {
    SeedProxyError,
    SeedProxyErrorCode,
    SAPPHIRE_MAINNET_CHAIN_ID,
    CONTRACT_ADDRESS,
    KEY_TYPE_SEED,
    KEY_TYPE_PRIVATE_KEY
} from './types';

// Type exports
export type { KeyType } from './types';

// Version - V2.0.0: Added Private Key support, KeyBridgeV9 contract
export const VERSION = '2.0.0';

// Default export
export { createSeedProxyClient as default } from './client';
