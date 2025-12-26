/**
 * Pribado Seed Proxy SDK
 * 
 * Main Client Class - HTTP-based integration for secure seed management
 * 
 * @author Ralph Lawrence Pecayo
 * @license MIT
 */

import { ethers } from 'ethers';
import {
    SeedProxyConfig,
    VaultInfo,
    RegisterVaultParams,
    RegisterVaultResult,
    AuthenticateParams,
    AuthenticateResult,
    SignMessageParams,
    SignMessageResult,
    SignTransactionParams,
    SignTransactionResult,
    VerifyKeyParams,
    VerifyKeyResult,
    RotateKeyParams,
    RotateKeyResult,
    RevokeKeyParams,
    RevokeKeyResult,
    ApiResponse,
    SeedProxyError,
    SeedProxyErrorCode
} from './types';
import {
    validateSeedPhrase,
    validatePrivateKey,
    validateAddress,
    encryptSeedPhrase,
    decryptSeedPhrase,
    generateProxyKeyId,
    hashProxyKey
} from './crypto';

// ============================================================================
// Seed Proxy Client
// ============================================================================

export class SeedProxyClient {
    private config: Required<SeedProxyConfig>;
    private abortController: AbortController | null = null;

    constructor(config: SeedProxyConfig) {
        if (!config.baseUrl) {
            throw new SeedProxyError(
                'baseUrl is required',
                SeedProxyErrorCode.INVALID_CONFIG
            );
        }

        this.config = {
            baseUrl: config.baseUrl.replace(/\/$/, ''), // Remove trailing slash
            apiKey: config.apiKey || '',
            defaultStorage: config.defaultStorage || 'l2s',
            timeout: config.timeout || 30000
        };
    }

    // =========================================================================
    // Vault Registration
    // =========================================================================

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
    async registerVault(params: RegisterVaultParams): Promise<RegisterVaultResult> {
        // Support both 'secret' and deprecated 'seedPhrase' params
        const secret = params.secret || params.seedPhrase || '';

        // Auto-detect key type if not provided
        const isPrivateKey = secret.startsWith('0x') && secret.length === 66;
        const keyType = params.keyType || (isPrivateKey ? 'privateKey' : 'seed');

        // Validate based on key type
        if (keyType === 'seed') {
            if (!validateSeedPhrase(secret)) {
                throw new SeedProxyError(
                    'Invalid seed phrase. Must be 12 or 24 words.',
                    SeedProxyErrorCode.INVALID_SEED_PHRASE
                );
            }
        } else if (keyType === 'privateKey') {
            if (!validatePrivateKey(secret)) {
                throw new SeedProxyError(
                    'Invalid private key. Must be 0x + 64 hex characters.',
                    SeedProxyErrorCode.INVALID_PRIVATE_KEY
                );
            }
        }

        // Validate password
        if (!params.password || params.password.length < 6) {
            throw new SeedProxyError(
                'Password must be at least 6 characters',
                SeedProxyErrorCode.INVALID_PASSWORD
            );
        }

        // Validate owner address
        if (!validateAddress(params.ownerAddress)) {
            throw new SeedProxyError(
                'Invalid owner address',
                SeedProxyErrorCode.INVALID_ADDRESS
            );
        }

        const storageType = params.storageType || this.config.defaultStorage;

        try {
            // Step 1: Encrypt secret (seed phrase or private key) client-side
            const encryptedSecret = await encryptSeedPhrase(secret, params.password);

            // Step 2: Generate proxy key ID
            const proxyKeyId = generateProxyKeyId(storageType === 'l2s');
            const keyHash = hashProxyKey(proxyKeyId);

            // Step 3: Send to API
            const response = await this.request<RegisterVaultResult>('/api/sdk/register', {
                method: 'POST',
                body: {
                    proxyKeyId,
                    keyHash,
                    encryptedSeed: encryptedSecret,
                    keyType, // 'seed' or 'privateKey'
                    label: params.label || 'Unnamed Vault',
                    ownerAddress: params.ownerAddress,
                    storageType
                }
            });

            if (!response.success) {
                throw new SeedProxyError(
                    response.error || 'Registration failed',
                    SeedProxyErrorCode.REGISTRATION_FAILED
                );
            }

            return {
                success: true,
                proxyKeyId,
                vaultIndex: response.data?.vaultIndex,
                txHash: response.data?.txHash
            };
        } catch (error) {
            if (error instanceof SeedProxyError) throw error;

            throw new SeedProxyError(
                'Failed to register vault',
                SeedProxyErrorCode.REGISTRATION_FAILED,
                error as Error
            );
        }
    }

    // =========================================================================
    // Authentication (Login with Proxy Key)
    // =========================================================================

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
    async authenticate(params: AuthenticateParams): Promise<AuthenticateResult> {
        if (!params.proxyKeyId || !params.proxyKeyId.startsWith('priv_')) {
            throw new SeedProxyError(
                'Invalid proxy key ID format',
                SeedProxyErrorCode.INVALID_KEY
            );
        }

        if (!params.password) {
            throw new SeedProxyError(
                'Password is required',
                SeedProxyErrorCode.INVALID_PASSWORD
            );
        }

        try {
            // Step 1: Verify key first
            const verification = await this.verifyKey({ proxyKeyId: params.proxyKeyId });

            if (!verification.exists || !verification.valid) {
                throw new SeedProxyError(
                    'Key not found or invalid',
                    SeedProxyErrorCode.KEY_NOT_FOUND
                );
            }

            if (!verification.isActive) {
                throw new SeedProxyError(
                    'Key has been revoked or already used',
                    SeedProxyErrorCode.KEY_INACTIVE
                );
            }

            // Step 2: Get encrypted seed from server
            const response = await this.request<{ encryptedSeed: string }>('/api/sdk/getSeed', {
                method: 'POST',
                body: {
                    proxyKeyId: params.proxyKeyId,
                    keyHash: hashProxyKey(params.proxyKeyId)
                }
            });

            if (!response.success || !response.data?.encryptedSeed) {
                throw new SeedProxyError(
                    response.error || 'Failed to retrieve seed',
                    SeedProxyErrorCode.AUTHENTICATION_FAILED
                );
            }

            // Step 3: Decrypt client-side
            let seedPhrase: string;
            try {
                seedPhrase = await decryptSeedPhrase(response.data.encryptedSeed, params.password);
            } catch {
                throw new SeedProxyError(
                    'Incorrect password',
                    SeedProxyErrorCode.INVALID_PASSWORD
                );
            }

            // Step 4: Rotate key for security
            const rotation = await this.rotateKey({
                proxyKeyId: params.proxyKeyId,
                password: params.password
            });

            return {
                success: true,
                seedPhrase,
                newProxyKeyId: rotation.newProxyKeyId
            };
        } catch (error) {
            if (error instanceof SeedProxyError) throw error;

            throw new SeedProxyError(
                'Authentication failed',
                SeedProxyErrorCode.AUTHENTICATION_FAILED,
                error as Error
            );
        }
    }

    // =========================================================================
    // Key Verification
    // =========================================================================

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
    async verifyKey(params: VerifyKeyParams): Promise<VerifyKeyResult> {
        try {
            const response = await this.request<VerifyKeyResult>('/api/keybridge', {
                method: 'GET',
                query: { proxyId: params.proxyKeyId }
            });

            return {
                exists: response.data?.exists || false,
                valid: response.data?.valid || response.data?.exists || false,
                isActive: response.data?.isActive || false,
                vaultIndex: response.data?.vaultIndex,
                type: response.data?.type
            };
        } catch {
            return {
                exists: false,
                valid: false,
                isActive: false
            };
        }
    }

    // =========================================================================
    // Key Rotation
    // =========================================================================

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
    async rotateKey(params: RotateKeyParams): Promise<RotateKeyResult> {
        const isL2S = params.proxyKeyId.startsWith('priv_secret');
        const newProxyKeyId = generateProxyKeyId(isL2S);
        const oldKeyHash = hashProxyKey(params.proxyKeyId);
        const newKeyHash = hashProxyKey(newProxyKeyId);

        try {
            const response = await this.request<{ success: boolean }>('/api/sdk/rotate', {
                method: 'POST',
                body: {
                    oldProxyKeyId: params.proxyKeyId,
                    oldKeyHash,
                    newKeyHash,
                    isL2S
                }
            });

            if (!response.success) {
                throw new SeedProxyError(
                    response.error || 'Rotation failed',
                    SeedProxyErrorCode.ROTATION_FAILED
                );
            }

            return {
                success: true,
                newProxyKeyId
            };
        } catch (error) {
            if (error instanceof SeedProxyError) throw error;

            throw new SeedProxyError(
                'Key rotation failed',
                SeedProxyErrorCode.ROTATION_FAILED,
                error as Error
            );
        }
    }

    // =========================================================================
    // Key Revocation
    // =========================================================================

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
    async revokeKey(params: RevokeKeyParams): Promise<RevokeKeyResult> {
        try {
            const response = await this.request<RevokeKeyResult>('/api/sdk/revoke', {
                method: 'POST',
                body: {
                    proxyKeyId: params.proxyKeyId,
                    keyHash: hashProxyKey(params.proxyKeyId)
                }
            });

            return {
                success: response.success,
                txHash: response.data?.txHash,
                error: response.error
            };
        } catch (error) {
            if (error instanceof SeedProxyError) throw error;

            throw new SeedProxyError(
                'Revocation failed',
                SeedProxyErrorCode.REVOCATION_FAILED,
                error as Error
            );
        }
    }

    // =========================================================================
    // List Vaults
    // =========================================================================

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
    async listVaults(ownerAddress: string): Promise<VaultInfo[]> {
        if (!validateAddress(ownerAddress)) {
            throw new SeedProxyError(
                'Invalid owner address',
                SeedProxyErrorCode.INVALID_ADDRESS
            );
        }

        try {
            const response = await this.request<{ vaults: VaultInfo[] }>('/api/sdk/vaults', {
                method: 'GET',
                query: { owner: ownerAddress }
            });

            return response.data?.vaults || [];
        } catch {
            return [];
        }
    }

    // =========================================================================
    // Message Signing (Advanced)
    // =========================================================================

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
    async signMessage(params: SignMessageParams): Promise<SignMessageResult> {
        try {
            // Get seed via authentication (but don't consume key - we'll handle that)
            const authResult = await this.authenticate({
                proxyKeyId: params.proxyKeyId,
                password: params.password
            });

            if (!authResult.success || !authResult.seedPhrase) {
                throw new SeedProxyError(
                    'Authentication failed',
                    SeedProxyErrorCode.AUTHENTICATION_FAILED
                );
            }

            // Create wallet from seed
            const wallet = ethers.Wallet.fromPhrase(authResult.seedPhrase);

            // Sign message
            const signature = await wallet.signMessage(params.message);
            const sig = ethers.Signature.from(signature);

            return {
                success: true,
                signature,
                v: sig.v,
                r: sig.r,
                s: sig.s,
                newProxyKeyId: authResult.newProxyKeyId,
                signerAddress: wallet.address
            };
        } catch (error) {
            if (error instanceof SeedProxyError) throw error;

            throw new SeedProxyError(
                'Signing failed',
                SeedProxyErrorCode.SIGNING_FAILED,
                error as Error
            );
        }
    }

    // =========================================================================
    // Transaction Signing (Advanced)
    // =========================================================================

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
    async signTransaction(params: SignTransactionParams): Promise<SignTransactionResult> {
        try {
            // Authenticate to get seed
            const authResult = await this.authenticate({
                proxyKeyId: params.proxyKeyId,
                password: params.password
            });

            if (!authResult.success || !authResult.seedPhrase) {
                throw new SeedProxyError(
                    'Authentication failed',
                    SeedProxyErrorCode.AUTHENTICATION_FAILED
                );
            }

            // Create wallet from seed
            const wallet = ethers.Wallet.fromPhrase(authResult.seedPhrase);

            // Prepare transaction
            const tx: ethers.TransactionRequest = {
                to: params.transaction.to,
                value: params.transaction.value ? BigInt(params.transaction.value) : undefined,
                data: params.transaction.data,
                nonce: params.transaction.nonce,
                gasLimit: params.transaction.gasLimit ? BigInt(params.transaction.gasLimit) : undefined,
                gasPrice: params.transaction.gasPrice ? BigInt(params.transaction.gasPrice) : undefined,
                maxFeePerGas: params.transaction.maxFeePerGas ? BigInt(params.transaction.maxFeePerGas) : undefined,
                maxPriorityFeePerGas: params.transaction.maxPriorityFeePerGas ? BigInt(params.transaction.maxPriorityFeePerGas) : undefined,
                chainId: params.transaction.chainId
            };

            // Sign transaction
            const signedTx = await wallet.signTransaction(tx);

            return {
                success: true,
                signedTransaction: signedTx
            };
        } catch (error) {
            if (error instanceof SeedProxyError) throw error;

            throw new SeedProxyError(
                'Transaction signing failed',
                SeedProxyErrorCode.SIGNING_FAILED,
                error as Error
            );
        }
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /**
     * Get the configured base URL
     */
    getBaseUrl(): string {
        return this.config.baseUrl;
    }

    /**
     * Get the default storage type
     */
    getDefaultStorage(): 'sapphire' | 'l2s' {
        return this.config.defaultStorage;
    }

    /**
     * Cancel any pending requests
     */
    cancelPendingRequests(): void {
        if (this.abortController) {
            this.abortController.abort();
            this.abortController = null;
        }
    }

    // =========================================================================
    // Private Methods
    // =========================================================================

    private async request<T>(
        endpoint: string,
        options: {
            method: 'GET' | 'POST' | 'DELETE';
            body?: Record<string, unknown>;
            query?: Record<string, string>;
        }
    ): Promise<ApiResponse<T>> {
        this.abortController = new AbortController();

        let url = `${this.config.baseUrl}${endpoint}`;

        if (options.query) {
            const params = new URLSearchParams(options.query);
            url += `?${params.toString()}`;
        }

        const headers: Record<string, string> = {
            'Content-Type': 'application/json'
        };

        if (this.config.apiKey) {
            headers['X-API-Key'] = this.config.apiKey;
        }

        try {
            const response = await fetch(url, {
                method: options.method,
                headers,
                body: options.body ? JSON.stringify(options.body) : undefined,
                signal: this.abortController.signal
            });

            const data = await response.json();

            if (!response.ok) {
                throw new SeedProxyError(
                    data.error || `HTTP ${response.status}`,
                    SeedProxyErrorCode.NETWORK_ERROR
                );
            }

            return data as ApiResponse<T>;
        } catch (error) {
            if (error instanceof SeedProxyError) throw error;

            if ((error as Error).name === 'AbortError') {
                throw new SeedProxyError(
                    'Request cancelled',
                    SeedProxyErrorCode.TIMEOUT
                );
            }

            throw new SeedProxyError(
                'Network error',
                SeedProxyErrorCode.NETWORK_ERROR,
                error as Error
            );
        }
    }
}

// ============================================================================
// Factory Function
// ============================================================================

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
export function createSeedProxyClient(config: SeedProxyConfig): SeedProxyClient {
    return new SeedProxyClient(config);
}
