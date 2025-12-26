/**
 * Pribado Seed Proxy SDK - Quick Start Examples
 * 
 * These examples demonstrate the SDK API using test vectors.
 * Note: This is reference code - actual implementation requires a running Pribado server.
 */

// For local development, use relative import:
import { createSeedProxyClient, VERSION } from '../src';
import { SAMPLE_SEED_1, SAMPLE_PK_1, SAMPLE_ADDR_1, SAMPLE_ADDR_2 } from './samples';

console.log(`Pribado SDK v${VERSION} - Examples\n`);

// Initialize client
const client = createSeedProxyClient({
    baseUrl: 'https://pribado.dev',
    defaultStorage: 'l2s'
});

// ============================================================================
// Example 1: Register a Seed Phrase
// ============================================================================

async function registerSeedPhrase() {
    console.log('[1] Registering seed phrase...');

    // Uses standardized test seed
    const result = await client.registerVault({
        secret: SAMPLE_SEED_1,
        password: 'demo-password-123',
        label: 'My Main Wallet',
        ownerAddress: SAMPLE_ADDR_1
    });

    console.log('[OK] Success!');
    console.log('    Proxy Key:', result.proxyKeyId);
    console.log('    Vault Index:', result.vaultIndex);
    console.log('    SAVE THIS KEY SECURELY!\n');

    return result.proxyKeyId;
}

// ============================================================================
// Example 2: Register a Private Key
// ============================================================================

async function registerPrivateKey() {
    console.log('[2] Registering private key...');

    // Uses standardized test private key
    const result = await client.registerVault({
        secret: SAMPLE_PK_1,
        password: 'demo-password-123',
        label: 'Trading Bot Key',
        ownerAddress: SAMPLE_ADDR_2,
        storageType: 'sapphire' // Use TEE for max security
    });

    console.log('[OK] Success!');
    console.log('    Proxy Key:', result.proxyKeyId);
    console.log('    Key Type: privateKey (auto-detected)\n');

    return result.proxyKeyId;
}

// ============================================================================
// Example 3: Authenticate and Recover Seed
// ============================================================================

async function authenticate(proxyKeyId: string) {
    console.log('[3] Authenticating...');

    const result = await client.authenticate({
        proxyKeyId,
        password: 'demo-password-123'
    });

    if (result.success) {
        console.log('[OK] Authentication successful!');
        console.log('    Recovered:', result.seedPhrase?.substring(0, 30) + '...');
        console.log('    NEW KEY:', result.newProxyKeyId);
        console.log('    (Old key is now invalid)\n');
    }

    return result.newProxyKeyId;
}

// ============================================================================
// Example 4: Sign a Message
// ============================================================================

async function signMessage(proxyKeyId: string) {
    console.log('[4] Signing message...');

    const result = await client.signMessage({
        proxyKeyId,
        password: 'demo-password-123',
        message: 'Hello, Web3!'
    });

    console.log('[OK] Signed!');
    console.log('    Signature:', result.signature?.substring(0, 40) + '...');
    console.log('    Signer:', result.signerAddress);
    console.log('    NEW KEY:', result.newProxyKeyId, '\n');
}

// ============================================================================
// Example 5: List Vaults
// ============================================================================

async function listVaults() {
    console.log('[5] Listing vaults...');

    const vaults = await client.listVaults(SAMPLE_ADDR_1);

    console.log(`[OK] Found ${vaults.length} vaults:`);
    vaults.forEach((v, i) => {
        console.log(`    ${i + 1}. ${v.label} (${v.type}, ${v.keyType})`);
    });
    console.log('');
}

// ============================================================================
// Run Examples
// ============================================================================

async function main() {
    try {
        // Uncomment to run:
        // const key1 = await registerSeedPhrase();
        // const key2 = await registerPrivateKey();
        // const newKey = await authenticate(key1);
        // await signMessage(newKey);
        // await listVaults();

        console.log('Uncomment examples in main() to run them.');
        console.log('Note: Requires a running Pribado server at the configured baseUrl.');
    } catch (error: any) {
        console.error('[ERROR]', error.message);
    }
}

main();
