// src/client.ts
import { ethers as ethers2 } from "ethers";

// src/types.ts
var SAPPHIRE_MAINNET_CHAIN_ID = 23294;
var CONTRACT_ADDRESS = "0xabE5D482AceFED95E0D37dA89bC63F941f02f9A0";
var KEY_TYPE_SEED = 0;
var KEY_TYPE_PRIVATE_KEY = 1;
var SeedProxyErrorCode = /* @__PURE__ */ ((SeedProxyErrorCode2) => {
  SeedProxyErrorCode2["INVALID_CONFIG"] = "INVALID_CONFIG";
  SeedProxyErrorCode2["MISSING_API_KEY"] = "MISSING_API_KEY";
  SeedProxyErrorCode2["INVALID_PASSWORD"] = "INVALID_PASSWORD";
  SeedProxyErrorCode2["INVALID_KEY"] = "INVALID_KEY";
  SeedProxyErrorCode2["KEY_NOT_FOUND"] = "KEY_NOT_FOUND";
  SeedProxyErrorCode2["KEY_INACTIVE"] = "KEY_INACTIVE";
  SeedProxyErrorCode2["AUTHENTICATION_FAILED"] = "AUTHENTICATION_FAILED";
  SeedProxyErrorCode2["INVALID_SEED_PHRASE"] = "INVALID_SEED_PHRASE";
  SeedProxyErrorCode2["INVALID_PRIVATE_KEY"] = "INVALID_PRIVATE_KEY";
  SeedProxyErrorCode2["INVALID_ADDRESS"] = "INVALID_ADDRESS";
  SeedProxyErrorCode2["INVALID_TRANSACTION"] = "INVALID_TRANSACTION";
  SeedProxyErrorCode2["REGISTRATION_FAILED"] = "REGISTRATION_FAILED";
  SeedProxyErrorCode2["SIGNING_FAILED"] = "SIGNING_FAILED";
  SeedProxyErrorCode2["ROTATION_FAILED"] = "ROTATION_FAILED";
  SeedProxyErrorCode2["REVOCATION_FAILED"] = "REVOCATION_FAILED";
  SeedProxyErrorCode2["NETWORK_ERROR"] = "NETWORK_ERROR";
  SeedProxyErrorCode2["TIMEOUT"] = "TIMEOUT";
  SeedProxyErrorCode2["RATE_LIMITED"] = "RATE_LIMITED";
  SeedProxyErrorCode2["GAS_LIMIT_EXCEEDED"] = "GAS_LIMIT_EXCEEDED";
  return SeedProxyErrorCode2;
})(SeedProxyErrorCode || {});
var SeedProxyError = class extends Error {
  constructor(message, code, cause) {
    super(message);
    this.code = code;
    this.cause = cause;
    this.name = "SeedProxyError";
  }
};

// src/crypto.ts
import { ethers } from "ethers";
function validateSeedPhrase(phrase) {
  if (!phrase || typeof phrase !== "string") return false;
  const words = phrase.trim().toLowerCase().split(/\s+/);
  if (words.length !== 12 && words.length !== 24) return false;
  return words.every((word) => /^[a-z]+$/.test(word));
}
function validatePrivateKey(key) {
  if (!key || typeof key !== "string") return false;
  const cleanKey = key.startsWith("0x") ? key.slice(2) : key;
  return /^[0-9a-fA-F]{64}$/.test(cleanKey);
}
function validateAddress(address) {
  try {
    return ethers.isAddress(address);
  } catch {
    return false;
  }
}
function generateProxyKeyId(isL2S = false) {
  const randomBytes = ethers.randomBytes(32);
  const hex = ethers.hexlify(randomBytes).slice(2);
  return isL2S ? `priv_secret${hex}` : `priv_${hex}`;
}
function hashProxyKey(proxyKeyId) {
  let keyBytes;
  if (proxyKeyId.startsWith("priv_secret")) {
    keyBytes = "0x" + proxyKeyId.slice(11);
  } else if (proxyKeyId.startsWith("priv_")) {
    keyBytes = "0x" + proxyKeyId.slice(5);
  } else {
    keyBytes = proxyKeyId;
  }
  return ethers.keccak256(ethers.solidityPacked(["bytes32"], [keyBytes]));
}
function parseProxyKey(proxyKeyId) {
  if (proxyKeyId.startsWith("priv_secret")) {
    return "0x" + proxyKeyId.slice(11);
  } else if (proxyKeyId.startsWith("priv_")) {
    return "0x" + proxyKeyId.slice(5);
  }
  return proxyKeyId;
}
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt.buffer,
      iterations: 1e5,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptSeedPhrase(seedPhrase, password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(seedPhrase);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);
  return btoa(String.fromCharCode(...combined));
}
async function decryptSeedPhrase(encryptedBlob, password) {
  const combined = Uint8Array.from(atob(encryptedBlob), (c) => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}
function wordToBytes32(word) {
  const bytes = ethers.toUtf8Bytes(word);
  const padded = ethers.zeroPadBytes(bytes, 32);
  return padded;
}
function bytes32ToWord(bytes32) {
  try {
    const hex = bytes32.replace(/0+$/, "");
    if (hex.length <= 2) return "";
    return ethers.toUtf8String(hex);
  } catch {
    return "";
  }
}
function encodeSeedWords(seedPhrase) {
  const wordList = seedPhrase.trim().split(/\s+/);
  const words = [];
  for (let i = 0; i < 12; i++) {
    if (i < wordList.length) {
      words.push(wordToBytes32(wordList[i]));
    } else {
      words.push(ethers.zeroPadBytes("0x", 32));
    }
  }
  return { words, count: wordList.length };
}
function decodeSeedWords(words, count) {
  const wordList = [];
  for (let i = 0; i < count; i++) {
    const word = bytes32ToWord(words[i]);
    if (word) wordList.push(word);
  }
  return wordList.join(" ");
}
function hashOwner(address) {
  return ethers.keccak256(ethers.solidityPacked(["address"], [address]));
}
function labelToBytes32(label) {
  const bytes = ethers.toUtf8Bytes(label.slice(0, 31));
  return ethers.zeroPadBytes(bytes, 32);
}
function bytes32ToLabel(bytes32) {
  try {
    const hex = bytes32.replace(/0+$/, "");
    if (hex.length <= 2) return "";
    return ethers.toUtf8String(hex);
  } catch {
    return "";
  }
}
function deriveAddress(seedPhrase) {
  try {
    const wallet = ethers.Wallet.fromPhrase(seedPhrase);
    return wallet.address;
  } catch {
    throw new Error("Invalid seed phrase");
  }
}

// src/client.ts
var SeedProxyClient = class {
  constructor(config) {
    this.abortController = null;
    if (!config.baseUrl) {
      throw new SeedProxyError(
        "baseUrl is required",
        "INVALID_CONFIG" /* INVALID_CONFIG */
      );
    }
    this.config = {
      baseUrl: config.baseUrl.replace(/\/$/, ""),
      // Remove trailing slash
      apiKey: config.apiKey || "",
      defaultStorage: config.defaultStorage || "l2s",
      timeout: config.timeout || 3e4
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
  async registerVault(params) {
    const secret = params.secret || params.seedPhrase || "";
    const isPrivateKey = secret.startsWith("0x") && secret.length === 66;
    const keyType = params.keyType || (isPrivateKey ? "privateKey" : "seed");
    if (keyType === "seed") {
      if (!validateSeedPhrase(secret)) {
        throw new SeedProxyError(
          "Invalid seed phrase. Must be 12 or 24 words.",
          "INVALID_SEED_PHRASE" /* INVALID_SEED_PHRASE */
        );
      }
    } else if (keyType === "privateKey") {
      if (!validatePrivateKey(secret)) {
        throw new SeedProxyError(
          "Invalid private key. Must be 0x + 64 hex characters.",
          "INVALID_PRIVATE_KEY" /* INVALID_PRIVATE_KEY */
        );
      }
    }
    if (!params.password || params.password.length < 6) {
      throw new SeedProxyError(
        "Password must be at least 6 characters",
        "INVALID_PASSWORD" /* INVALID_PASSWORD */
      );
    }
    if (!validateAddress(params.ownerAddress)) {
      throw new SeedProxyError(
        "Invalid owner address",
        "INVALID_ADDRESS" /* INVALID_ADDRESS */
      );
    }
    const storageType = params.storageType || this.config.defaultStorage;
    try {
      const encryptedSecret = await encryptSeedPhrase(secret, params.password);
      const proxyKeyId = generateProxyKeyId(storageType === "l2s");
      const keyHash = hashProxyKey(proxyKeyId);
      const response = await this.request("/api/sdk/register", {
        method: "POST",
        body: {
          proxyKeyId,
          keyHash,
          encryptedSeed: encryptedSecret,
          keyType,
          // 'seed' or 'privateKey'
          label: params.label || "Unnamed Vault",
          ownerAddress: params.ownerAddress,
          storageType
        }
      });
      if (!response.success) {
        throw new SeedProxyError(
          response.error || "Registration failed",
          "REGISTRATION_FAILED" /* REGISTRATION_FAILED */
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
        "Failed to register vault",
        "REGISTRATION_FAILED" /* REGISTRATION_FAILED */,
        error
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
  async authenticate(params) {
    if (!params.proxyKeyId || !params.proxyKeyId.startsWith("priv_")) {
      throw new SeedProxyError(
        "Invalid proxy key ID format",
        "INVALID_KEY" /* INVALID_KEY */
      );
    }
    if (!params.password) {
      throw new SeedProxyError(
        "Password is required",
        "INVALID_PASSWORD" /* INVALID_PASSWORD */
      );
    }
    try {
      const verification = await this.verifyKey({ proxyKeyId: params.proxyKeyId });
      if (!verification.exists || !verification.valid) {
        throw new SeedProxyError(
          "Key not found or invalid",
          "KEY_NOT_FOUND" /* KEY_NOT_FOUND */
        );
      }
      if (!verification.isActive) {
        throw new SeedProxyError(
          "Key has been revoked or already used",
          "KEY_INACTIVE" /* KEY_INACTIVE */
        );
      }
      const response = await this.request("/api/sdk/getSeed", {
        method: "POST",
        body: {
          proxyKeyId: params.proxyKeyId,
          keyHash: hashProxyKey(params.proxyKeyId)
        }
      });
      if (!response.success || !response.data?.encryptedSeed) {
        throw new SeedProxyError(
          response.error || "Failed to retrieve seed",
          "AUTHENTICATION_FAILED" /* AUTHENTICATION_FAILED */
        );
      }
      let seedPhrase;
      try {
        seedPhrase = await decryptSeedPhrase(response.data.encryptedSeed, params.password);
      } catch {
        throw new SeedProxyError(
          "Incorrect password",
          "INVALID_PASSWORD" /* INVALID_PASSWORD */
        );
      }
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
        "Authentication failed",
        "AUTHENTICATION_FAILED" /* AUTHENTICATION_FAILED */,
        error
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
  async verifyKey(params) {
    try {
      const response = await this.request("/api/keybridge", {
        method: "GET",
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
  async rotateKey(params) {
    const isL2S = params.proxyKeyId.startsWith("priv_secret");
    const newProxyKeyId = generateProxyKeyId(isL2S);
    const oldKeyHash = hashProxyKey(params.proxyKeyId);
    const newKeyHash = hashProxyKey(newProxyKeyId);
    try {
      const response = await this.request("/api/sdk/rotate", {
        method: "POST",
        body: {
          oldProxyKeyId: params.proxyKeyId,
          oldKeyHash,
          newKeyHash,
          isL2S
        }
      });
      if (!response.success) {
        throw new SeedProxyError(
          response.error || "Rotation failed",
          "ROTATION_FAILED" /* ROTATION_FAILED */
        );
      }
      return {
        success: true,
        newProxyKeyId
      };
    } catch (error) {
      if (error instanceof SeedProxyError) throw error;
      throw new SeedProxyError(
        "Key rotation failed",
        "ROTATION_FAILED" /* ROTATION_FAILED */,
        error
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
  async revokeKey(params) {
    try {
      const response = await this.request("/api/sdk/revoke", {
        method: "POST",
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
        "Revocation failed",
        "REVOCATION_FAILED" /* REVOCATION_FAILED */,
        error
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
  async listVaults(ownerAddress) {
    if (!validateAddress(ownerAddress)) {
      throw new SeedProxyError(
        "Invalid owner address",
        "INVALID_ADDRESS" /* INVALID_ADDRESS */
      );
    }
    try {
      const response = await this.request("/api/sdk/vaults", {
        method: "GET",
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
  async signMessage(params) {
    try {
      const authResult = await this.authenticate({
        proxyKeyId: params.proxyKeyId,
        password: params.password
      });
      if (!authResult.success || !authResult.seedPhrase) {
        throw new SeedProxyError(
          "Authentication failed",
          "AUTHENTICATION_FAILED" /* AUTHENTICATION_FAILED */
        );
      }
      const wallet = ethers2.Wallet.fromPhrase(authResult.seedPhrase);
      const signature = await wallet.signMessage(params.message);
      const sig = ethers2.Signature.from(signature);
      return {
        success: true,
        signature,
        v: sig.v,
        r: sig.r,
        s: sig.s
      };
    } catch (error) {
      if (error instanceof SeedProxyError) throw error;
      throw new SeedProxyError(
        "Signing failed",
        "SIGNING_FAILED" /* SIGNING_FAILED */,
        error
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
  async signTransaction(params) {
    try {
      const authResult = await this.authenticate({
        proxyKeyId: params.proxyKeyId,
        password: params.password
      });
      if (!authResult.success || !authResult.seedPhrase) {
        throw new SeedProxyError(
          "Authentication failed",
          "AUTHENTICATION_FAILED" /* AUTHENTICATION_FAILED */
        );
      }
      const wallet = ethers2.Wallet.fromPhrase(authResult.seedPhrase);
      const tx = {
        to: params.transaction.to,
        value: params.transaction.value ? BigInt(params.transaction.value) : void 0,
        data: params.transaction.data,
        nonce: params.transaction.nonce,
        gasLimit: params.transaction.gasLimit ? BigInt(params.transaction.gasLimit) : void 0,
        gasPrice: params.transaction.gasPrice ? BigInt(params.transaction.gasPrice) : void 0,
        maxFeePerGas: params.transaction.maxFeePerGas ? BigInt(params.transaction.maxFeePerGas) : void 0,
        maxPriorityFeePerGas: params.transaction.maxPriorityFeePerGas ? BigInt(params.transaction.maxPriorityFeePerGas) : void 0,
        chainId: params.transaction.chainId
      };
      const signedTx = await wallet.signTransaction(tx);
      return {
        success: true,
        signedTransaction: signedTx
      };
    } catch (error) {
      if (error instanceof SeedProxyError) throw error;
      throw new SeedProxyError(
        "Transaction signing failed",
        "SIGNING_FAILED" /* SIGNING_FAILED */,
        error
      );
    }
  }
  // =========================================================================
  // Utility Methods
  // =========================================================================
  /**
   * Get the configured base URL
   */
  getBaseUrl() {
    return this.config.baseUrl;
  }
  /**
   * Get the default storage type
   */
  getDefaultStorage() {
    return this.config.defaultStorage;
  }
  /**
   * Cancel any pending requests
   */
  cancelPendingRequests() {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }
  // =========================================================================
  // Private Methods
  // =========================================================================
  async request(endpoint, options) {
    this.abortController = new AbortController();
    let url = `${this.config.baseUrl}${endpoint}`;
    if (options.query) {
      const params = new URLSearchParams(options.query);
      url += `?${params.toString()}`;
    }
    const headers = {
      "Content-Type": "application/json"
    };
    if (this.config.apiKey) {
      headers["X-API-Key"] = this.config.apiKey;
    }
    try {
      const response = await fetch(url, {
        method: options.method,
        headers,
        body: options.body ? JSON.stringify(options.body) : void 0,
        signal: this.abortController.signal
      });
      const data = await response.json();
      if (!response.ok) {
        throw new SeedProxyError(
          data.error || `HTTP ${response.status}`,
          "NETWORK_ERROR" /* NETWORK_ERROR */
        );
      }
      return data;
    } catch (error) {
      if (error instanceof SeedProxyError) throw error;
      if (error.name === "AbortError") {
        throw new SeedProxyError(
          "Request cancelled",
          "TIMEOUT" /* TIMEOUT */
        );
      }
      throw new SeedProxyError(
        "Network error",
        "NETWORK_ERROR" /* NETWORK_ERROR */,
        error
      );
    }
  }
};
function createSeedProxyClient(config) {
  return new SeedProxyClient(config);
}

// src/index.ts
var VERSION = "2.0.0";
export {
  CONTRACT_ADDRESS,
  KEY_TYPE_PRIVATE_KEY,
  KEY_TYPE_SEED,
  SAPPHIRE_MAINNET_CHAIN_ID,
  SeedProxyClient,
  SeedProxyError,
  SeedProxyErrorCode,
  VERSION,
  bytes32ToLabel,
  createSeedProxyClient,
  decodeSeedWords,
  decryptSeedPhrase,
  createSeedProxyClient as default,
  deriveAddress,
  encodeSeedWords,
  encryptSeedPhrase,
  generateProxyKeyId,
  hashOwner,
  hashProxyKey,
  labelToBytes32,
  parseProxyKey,
  validateAddress,
  validatePrivateKey,
  validateSeedPhrase
};
/**
 * Pribado Seed Proxy SDK
 * 
 * Main Client Class - HTTP-based integration for secure seed management
 * 
 * @author Ralph Lawrence Pecayo
 * @license MIT
 */
/**
 * Pribado Seed Proxy SDK
 * 
 * Secure encrypted endpoints for Web3 wallets
 * 
 * @packageDocumentation
 * @author Ralph Lawrence Pecayo
 * @license MIT
 */
