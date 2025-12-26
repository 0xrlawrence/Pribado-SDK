/**
 * Pribado Seed Proxy SDK - React Hook Example
 * 
 * A simple React hook for integrating Pribado SDK
 */

import { useState, useCallback, useMemo } from 'react';
import {
    createSeedProxyClient,
    SeedProxyClient,
    RegisterVaultParams,
    RegisterVaultResult,
    AuthenticateParams,
    AuthenticateResult,
    SignMessageParams,
    SignMessageResult
} from '@pribado/seed-proxy-sdk';

interface UsePribadoOptions {
    baseUrl: string;
    defaultStorage?: 'sapphire' | 'l2s';
}

interface UsePribadoReturn {
    // State
    isLoading: boolean;
    error: string | null;

    // Methods
    registerVault: (params: RegisterVaultParams) => Promise<RegisterVaultResult>;
    authenticate: (params: AuthenticateParams) => Promise<AuthenticateResult>;
    signMessage: (params: SignMessageParams) => Promise<SignMessageResult>;
    clearError: () => void;
}

/**
 * React hook for Pribado Seed Proxy SDK
 * 
 * @example
 * ```tsx
 * const { registerVault, authenticate, isLoading, error } = usePribado({
 *   baseUrl: 'https://pribado.dev'
 * });
 * 
 * const handleRegister = async () => {
 *   const result = await registerVault({
 *     secret: seedPhrase,
 *     password: password,
 *     ownerAddress: address
 *   });
 *   console.log('Proxy Key:', result.proxyKeyId);
 * };
 * ```
 */
export function usePribado(options: UsePribadoOptions): UsePribadoReturn {
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Create client instance (memoized)
    const client: SeedProxyClient = useMemo(() => {
        return createSeedProxyClient({
            baseUrl: options.baseUrl,
            defaultStorage: options.defaultStorage || 'l2s'
        });
    }, [options.baseUrl, options.defaultStorage]);

    // Clear error
    const clearError = useCallback(() => {
        setError(null);
    }, []);

    // Register vault wrapper
    const registerVault = useCallback(async (params: RegisterVaultParams): Promise<RegisterVaultResult> => {
        setIsLoading(true);
        setError(null);

        try {
            const result = await client.registerVault(params);
            return result;
        } catch (e: any) {
            setError(e.message || 'Registration failed');
            throw e;
        } finally {
            setIsLoading(false);
        }
    }, [client]);

    // Authenticate wrapper
    const authenticate = useCallback(async (params: AuthenticateParams): Promise<AuthenticateResult> => {
        setIsLoading(true);
        setError(null);

        try {
            const result = await client.authenticate(params);
            return result;
        } catch (e: any) {
            setError(e.message || 'Authentication failed');
            throw e;
        } finally {
            setIsLoading(false);
        }
    }, [client]);

    // Sign message wrapper
    const signMessage = useCallback(async (params: SignMessageParams): Promise<SignMessageResult> => {
        setIsLoading(true);
        setError(null);

        try {
            const result = await client.signMessage(params);
            return result;
        } catch (e: any) {
            setError(e.message || 'Signing failed');
            throw e;
        } finally {
            setIsLoading(false);
        }
    }, [client]);

    return {
        isLoading,
        error,
        registerVault,
        authenticate,
        signMessage,
        clearError
    };
}

export default usePribado;
