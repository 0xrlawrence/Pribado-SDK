/**
 * Pribado Seed Proxy SDK - React Component Example
 * 
 * A complete registration form component
 */

import React, { useState } from 'react';
import { usePribado } from './react-hook';

interface RegisterFormProps {
    ownerAddress: string;
    onSuccess: (proxyKeyId: string) => void;
}

export function PribadoRegisterForm({ ownerAddress, onSuccess }: RegisterFormProps) {
    const { registerVault, isLoading, error, clearError } = usePribado({
        baseUrl: 'https://pribado.dev',
        defaultStorage: 'l2s'
    });

    const [secret, setSecret] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [label, setLabel] = useState('');
    const [storageType, setStorageType] = useState<'l2s' | 'sapphire'>('l2s');

    // Auto-detect key type
    const isPrivateKey = secret.startsWith('0x') && secret.length === 66;
    const keyType = isPrivateKey ? 'Private Key' : 'Seed Phrase';

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        clearError();

        if (password !== confirmPassword) {
            alert('Passwords do not match');
            return;
        }

        if (password.length < 6) {
            alert('Password must be at least 6 characters');
            return;
        }

        try {
            const result = await registerVault({
                secret,
                password,
                label: label || undefined,
                ownerAddress,
                storageType
            });

            if (result.success) {
                alert(`Success! Save your proxy key:\n\n${result.proxyKeyId}`);
                onSuccess(result.proxyKeyId);
            }
        } catch (err) {
            // Error is handled by hook
        }
    };

    return (
        <form onSubmit={handleSubmit} style={styles.form}>
            <h2 style={styles.title}>Register Secure Key</h2>

            {/* Secret Input */}
            <div style={styles.field}>
                <label style={styles.label}>
                    Seed Phrase or Private Key
                    <span style={styles.badge}>{keyType}</span>
                </label>
                <textarea
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    placeholder="Enter 12-word seed phrase or 0x... private key"
                    rows={3}
                    style={styles.textarea}
                    required
                />
            </div>

            {/* Password */}
            <div style={styles.field}>
                <label style={styles.label}>Encryption Password</label>
                <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 6 characters"
                    style={styles.input}
                    required
                    minLength={6}
                />
            </div>

            {/* Confirm Password */}
            <div style={styles.field}>
                <label style={styles.label}>Confirm Password</label>
                <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-enter password"
                    style={styles.input}
                    required
                />
            </div>

            {/* Label */}
            <div style={styles.field}>
                <label style={styles.label}>Label (optional)</label>
                <input
                    type="text"
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    placeholder="My Main Wallet"
                    style={styles.input}
                />
            </div>

            {/* Storage Type */}
            <div style={styles.field}>
                <label style={styles.label}>Storage Type</label>
                <div style={styles.radioGroup}>
                    <label style={styles.radioLabel}>
                        <input
                            type="radio"
                            name="storage"
                            value="l2s"
                            checked={storageType === 'l2s'}
                            onChange={() => setStorageType('l2s')}
                        />
                        <span>L2S (Fast, No Gas)</span>
                    </label>
                    <label style={styles.radioLabel}>
                        <input
                            type="radio"
                            name="storage"
                            value="sapphire"
                            checked={storageType === 'sapphire'}
                            onChange={() => setStorageType('sapphire')}
                        />
                        <span>Sapphire TEE (Max Security)</span>
                    </label>
                </div>
            </div>

            {/* Error */}
            {error && <div style={styles.error}>Error: {error}</div>}

            {/* Submit */}
            <button
                type="submit"
                disabled={isLoading}
                style={{
                    ...styles.button,
                    opacity: isLoading ? 0.6 : 1
                }}
            >
                {isLoading ? 'Encrypting...' : 'Register & Encrypt'}
            </button>
        </form>
    );
}

// Simple inline styles
const styles: Record<string, React.CSSProperties> = {
    form: {
        maxWidth: 400,
        margin: '0 auto',
        padding: 24,
        backgroundColor: '#1a1a2e',
        borderRadius: 12,
        color: '#fff'
    },
    title: {
        marginBottom: 20,
        textAlign: 'center'
    },
    field: {
        marginBottom: 16
    },
    label: {
        display: 'block',
        marginBottom: 6,
        fontSize: 14,
        fontWeight: 500
    },
    badge: {
        marginLeft: 8,
        padding: '2px 8px',
        backgroundColor: '#4ade80',
        color: '#000',
        borderRadius: 12,
        fontSize: 11,
        fontWeight: 600
    },
    input: {
        width: '100%',
        padding: 12,
        backgroundColor: '#0f0f23',
        border: '1px solid #333',
        borderRadius: 8,
        color: '#fff',
        fontSize: 14
    },
    textarea: {
        width: '100%',
        padding: 12,
        backgroundColor: '#0f0f23',
        border: '1px solid #333',
        borderRadius: 8,
        color: '#fff',
        fontSize: 14,
        resize: 'vertical' as const
    },
    radioGroup: {
        display: 'flex',
        gap: 16
    },
    radioLabel: {
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        cursor: 'pointer'
    },
    error: {
        marginBottom: 16,
        padding: 12,
        backgroundColor: '#ff4444',
        borderRadius: 8,
        fontSize: 14
    },
    button: {
        width: '100%',
        padding: 14,
        backgroundColor: '#4ade80',
        border: 'none',
        borderRadius: 8,
        color: '#000',
        fontSize: 16,
        fontWeight: 600,
        cursor: 'pointer'
    }
};

export default PribadoRegisterForm;
