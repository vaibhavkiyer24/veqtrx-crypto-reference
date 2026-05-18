/**
 * Veqtrx zero-knowledge envelope encryption — reference implementation.
 *
 * This is the actual code that runs in every Veqtrx user's browser. It is
 * published here so that anyone — banks doing vendor due diligence,
 * security researchers, regulators, customers — can verify that:
 *
 *   1. The server never sees plaintext customer data.
 *   2. The server never sees a key capable of decrypting it.
 *   3. The customer's password never leaves the browser.
 *
 * The same file is committed verbatim to the private application repo;
 * the public copy here lets you diff and confirm equivalence.
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │  THREE PRINCIPALS · ONE DEK PER BUDGET · KEY MATERIAL NEVER UPLOADED │
 * └──────────────────────────────────────────────────────────────────────┘
 *
 *   1. CUSTOMER
 *      KEK_customer = PBKDF2(password, customer.salt, 600k iterations,
 *                             SHA-256, 32 bytes)
 *      Each budget has a fresh 256-bit AES-GCM DEK; the DEK is wrapped
 *      with KEK_customer at save time. The KEK is non-extractable in
 *      the browser; the password is discarded after KEK derivation.
 *
 *   2. AGENT (debt advisor)
 *      Each agent has an RSA-OAEP-2048 keypair generated in their
 *      browser at bootstrap. The public key is uploaded plaintext; the
 *      private key is wrapped with KEK_agent (PBKDF2 of agent password)
 *      and uploaded. To grant an agent access to a budget, the customer
 *      fetches the agent's public key and RSA-wraps the DEK to it. The
 *      server stores only the wrapped DEK.
 *
 *   3. CREDITOR (lender, with revocable share link)
 *      Customer generates a random 32-byte share token, imports it as
 *      an AES-GCM key, wraps the DEK with that key, sends the wrapped
 *      DEK to the server. The token itself lives only in the share URL
 *      (after the `#`, so it never reaches the server in normal HTTP
 *      logs). Anyone with the URL can derive the key and unwrap.
 *      Anyone without it — including the server — cannot.
 *
 * All cryptographic operations use the Web Crypto API (`crypto.subtle`).
 * No third-party crypto libraries are imported. The audit surface is
 * exactly the code in this file plus the host browser's Web Crypto
 * implementation.
 *
 * License: MIT (see ../LICENSE).
 */

// ── Constants ────────────────────────────────────────────────────────────────

export const ZK_VERSION = 2;
export const PBKDF2_ITERATIONS_DEFAULT = 600_000;
export const PBKDF2_HASH = "SHA-256" as const;
export const KEK_BITS = 256;
export const DEK_BITS = 256;
export const RSA_MODULUS_BITS = 2048;
export const AES_GCM_NONCE_BYTES = 12;
export const AES_GCM_TAG_BITS = 128;
export const SALT_BYTES = 32;

// ── Base64 helpers (URL-safe and standard) ───────────────────────────────────

export function bytesToBase64(bytes: Uint8Array<ArrayBuffer>): string {
  let s = "";
  for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(b64u: string): Uint8Array<ArrayBuffer> {
  const pad = b64u.length % 4 === 0 ? "" : "=".repeat(4 - (b64u.length % 4));
  return base64ToBytes(b64u.replace(/-/g, "+").replace(/_/g, "/") + pad);
}

// ── Key derivation ──────────────────────────────────────────────────────────

export function generateSalt(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

/**
 * Derive a Key Encryption Key (KEK) from a password.
 *
 * The returned CryptoKey is non-extractable: even the calling code cannot
 * read its bytes back out, which limits the blast radius of an XSS that
 * pulls JS-accessible state. Cost: ~600-900 ms on a modern phone at 600k
 * iterations. Run on login only; cache the resulting CryptoKey in memory.
 */
export async function deriveKEK(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number = PBKDF2_ITERATIONS_DEFAULT
): Promise<CryptoKey> {
  if (iterations < 100_000) {
    throw new Error(`PBKDF2 iterations too low (${iterations}); minimum 100k`);
  }
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: PBKDF2_HASH },
    baseKey,
    { name: "AES-GCM", length: KEK_BITS },
    /* extractable */ false,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
  );
}

// ── DEK lifecycle ────────────────────────────────────────────────────────────

export async function generateDEK(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: DEK_BITS },
    /* extractable */ true,
    ["encrypt", "decrypt"]
  );
}

// ── Symmetric wrap/unwrap (KEK <-> DEK) ──────────────────────────────────────

/** Wrap a DEK under a symmetric KEK using AES-GCM. Output: nonce(12) || ct. */
export async function wrapDEKWithKEK(
  dek: CryptoKey,
  kek: CryptoKey
): Promise<Uint8Array<ArrayBuffer>> {
  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
  const wrapped = await crypto.subtle.wrapKey(
    "raw",
    dek,
    kek,
    { name: "AES-GCM", iv: nonce, tagLength: AES_GCM_TAG_BITS }
  );
  const out = new Uint8Array(nonce.byteLength + wrapped.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(wrapped), nonce.byteLength);
  return out;
}

/** Reverse of wrapDEKWithKEK. */
export async function unwrapDEKWithKEK(
  wrappedDek: Uint8Array<ArrayBuffer>,
  kek: CryptoKey
): Promise<CryptoKey> {
  const nonce = wrappedDek.slice(0, AES_GCM_NONCE_BYTES);
  const ct = wrappedDek.slice(AES_GCM_NONCE_BYTES);
  return crypto.subtle.unwrapKey(
    "raw",
    ct,
    kek,
    { name: "AES-GCM", iv: nonce, tagLength: AES_GCM_TAG_BITS },
    { name: "AES-GCM", length: DEK_BITS },
    /* extractable */ true,
    ["encrypt", "decrypt"]
  );
}

// ── Payload encrypt/decrypt with DEK ─────────────────────────────────────────

export interface EncryptedBlob {
  blob: string;          // base64(nonce || ciphertext || tag)
  integrityHash: string; // sha-256 hex of plaintext JSON
}

export async function encryptBlob(plaintext: unknown, dek: CryptoKey): Promise<EncryptedBlob> {
  const json = JSON.stringify(plaintext);
  const ptBytes = new TextEncoder().encode(json);

  const hashBuf = await crypto.subtle.digest("SHA-256", ptBytes);
  const integrityHash = Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: AES_GCM_TAG_BITS },
    dek,
    ptBytes
  );

  const combined = new Uint8Array(nonce.byteLength + ctBuf.byteLength);
  combined.set(nonce, 0);
  combined.set(new Uint8Array(ctBuf), nonce.byteLength);
  return { blob: bytesToBase64(combined), integrityHash };
}

export async function decryptBlob(blobB64: string, dek: CryptoKey): Promise<unknown> {
  const combined = base64ToBytes(blobB64);
  const nonce = combined.slice(0, AES_GCM_NONCE_BYTES);
  const ct = combined.slice(AES_GCM_NONCE_BYTES);
  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, tagLength: AES_GCM_TAG_BITS },
    dek,
    ct
  );
  return JSON.parse(new TextDecoder().decode(ptBuf));
}

// ── Asymmetric (agent flow) ──────────────────────────────────────────────────

export interface AgentKeypair {
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey;
  privateKeyPkcs8: ArrayBuffer;
}

export async function generateAgentKeypair(): Promise<AgentKeypair> {
  const keypair = (await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_MODULUS_BITS,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: PBKDF2_HASH,
    },
    /* extractable */ true,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
  )) as CryptoKeyPair;

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keypair.publicKey);
  const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", keypair.privateKey);

  return { publicKeyJwk, privateKey: keypair.privateKey, privateKeyPkcs8 };
}

export async function importAgentPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: PBKDF2_HASH },
    false,
    ["wrapKey", "encrypt"]
  );
}

export async function wrapPrivateKeyWithKEK(
  privateKeyPkcs8: ArrayBuffer,
  kek: CryptoKey
): Promise<Uint8Array<ArrayBuffer>> {
  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: AES_GCM_TAG_BITS },
    kek,
    privateKeyPkcs8
  );
  const out = new Uint8Array(nonce.byteLength + ct.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(ct), nonce.byteLength);
  return out;
}

export async function unwrapPrivateKeyWithKEK(
  wrapped: Uint8Array<ArrayBuffer>,
  kek: CryptoKey
): Promise<CryptoKey> {
  const nonce = wrapped.slice(0, AES_GCM_NONCE_BYTES);
  const ct = wrapped.slice(AES_GCM_NONCE_BYTES);
  const pkcs8 = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, tagLength: AES_GCM_TAG_BITS },
    kek,
    ct
  );
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSA-OAEP", hash: PBKDF2_HASH },
    /* extractable */ false,
    ["unwrapKey", "decrypt"]
  );
}

export async function wrapDEKToAgent(
  dek: CryptoKey,
  agentPublicKey: CryptoKey
): Promise<Uint8Array<ArrayBuffer>> {
  const wrapped = await crypto.subtle.wrapKey(
    "raw",
    dek,
    agentPublicKey,
    { name: "RSA-OAEP" }
  );
  return new Uint8Array(wrapped);
}

export async function unwrapDEKWithAgentPrivate(
  wrapped: Uint8Array<ArrayBuffer>,
  agentPrivateKey: CryptoKey
): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    agentPrivateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: DEK_BITS },
    /* extractable */ true,
    ["encrypt", "decrypt"]
  );
}

// ── Creditor share-token flow ────────────────────────────────────────────────

export function generateShareToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64Url(bytes);
}

/**
 * Import a 32-byte share token directly as an AES-GCM key.
 *
 * The token is itself 256 bits of randomness — no slow KDF needed. PBKDF2
 * only adds value when the input is low-entropy. Anyone with the URL holds
 * 256 bits of secret; anyone without it has zero.
 */
export async function deriveShareKey(token: string): Promise<CryptoKey> {
  const bytes = base64UrlToBytes(token);
  if (bytes.byteLength !== 32) {
    throw new Error(`Invalid share token length: ${bytes.byteLength} (expected 32)`);
  }
  return crypto.subtle.importKey(
    "raw",
    bytes,
    { name: "AES-GCM", length: KEK_BITS },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

export async function wrapDEKWithShareKey(
  dek: CryptoKey,
  shareKey: CryptoKey
): Promise<Uint8Array<ArrayBuffer>> {
  return wrapDEKWithKEK(dek, shareKey);
}

export async function unwrapDEKWithShareKey(
  wrapped: Uint8Array<ArrayBuffer>,
  shareKey: CryptoKey
): Promise<CryptoKey> {
  return unwrapDEKWithKEK(wrapped, shareKey);
}
