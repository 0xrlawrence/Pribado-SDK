/**
 * Pribado Seed Proxy SDK - Test Samples
 * 
 * WARNING: THESE ARE PUBLIC KNOWN KEYS. DO NOT USE FOR REAL FUNDS!
 * These are strictly for testing the SDK integration in development environments.
 */

// Sample 1: Standard Test Mnemonic
export const SAMPLE_SEED_1 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
export const SAMPLE_PK_1 = '0xa8b294d1c5977795c9be902d5a57210c458fbf42d7a091aa70a1a28c12747335';
export const SAMPLE_ADDR_1 = '0x99537d92F64bb2481A0589d3A16A0AD201A04132';

// Sample 2
export const SAMPLE_SEED_2 = 'test test test test test test test test test test test junk';
export const SAMPLE_PK_2 = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // Common Hardhat Account 0
export const SAMPLE_ADDR_2 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

// Sample 3
export const SAMPLE_SEED_3 = 'myth like bonus scare over problem client lizard pioneer submit female collect';
export const SAMPLE_PK_3 = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // Common Hardhat Account 1
export const SAMPLE_ADDR_3 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

// Sample 4
export const SAMPLE_SEED_4 = 'shrimp express use car shift hole script mom rare put rice guard';
export const SAMPLE_PK_4 = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // Common Hardhat Account 2
export const SAMPLE_ADDR_4 = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';

// Sample 5
export const SAMPLE_SEED_5 = 'explain tackle hen amazing candle casual prefer voyage hotel history start private';
export const SAMPLE_PK_5 = '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'; // Common Hardhat Account 3
export const SAMPLE_ADDR_5 = '0x90F79bf6EB2c4f870365E785982E1f101E93b906';

// All Samples Collection
export const TEST_VECTORS = [
    {
        id: 1,
        seed: SAMPLE_SEED_1,
        privateKey: SAMPLE_PK_1,
        address: SAMPLE_ADDR_1,
        description: 'BIP39 Test Vector 1'
    },
    {
        id: 2,
        seed: SAMPLE_SEED_2,
        privateKey: SAMPLE_PK_2,
        address: SAMPLE_ADDR_2,
        description: 'Hardhat Account 0'
    },
    {
        id: 3,
        seed: SAMPLE_SEED_3,
        privateKey: SAMPLE_PK_3,
        address: SAMPLE_ADDR_3,
        description: 'Hardhat Account 1'
    },
    {
        id: 4,
        seed: SAMPLE_SEED_4,
        privateKey: SAMPLE_PK_4,
        address: SAMPLE_ADDR_4,
        description: 'Hardhat Account 2'
    },
    {
        id: 5,
        seed: SAMPLE_SEED_5,
        privateKey: SAMPLE_PK_5,
        address: SAMPLE_ADDR_5,
        description: 'Hardhat Account 3'
    }
];
