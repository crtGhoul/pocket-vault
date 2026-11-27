// Client-side AES-256-GCM encryption with PBKDF2 key derivation.
// Nothing leaves the device; the encryption key lives only in memory while unlocked.

const PBKDF2_ITERATIONS = 100000;
const VERIFY_PLAINTEXT = 'pocketvault-key-check-v1';

export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

export async function deriveKey(pin, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    bytes
  );
  return {
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(ciphertext))
  };
}

export async function decryptBytes(key, payload) {
  const iv = new Uint8Array(payload.iv);
  const data = new Uint8Array(payload.data);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  return new Uint8Array(plaintext);
}

export async function encryptJSON(key, value) {
  const enc = new TextEncoder();
  return encryptBytes(key, enc.encode(JSON.stringify(value)));
}

export async function decryptJSON(key, payload) {
  const bytes = await decryptBytes(key, payload);
  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function createVerifier(key) {
  return encryptJSON(key, { check: VERIFY_PLAINTEXT });
}

export async function verifyKey(key, verifierPayload) {
  try {
    const res = await decryptJSON(key, verifierPayload);
    return res && res.check === VERIFY_PLAINTEXT;
  } catch {
    return false;
  }
}
