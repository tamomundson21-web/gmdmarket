import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const AAD_CONTEXT = Buffer.from('trade-platform:tc-identity:v1', 'ascii');
const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const CRYPTO_VERSION = 'tc-aes-256-gcm-v1';

let keyMaterial: Buffer | null = null;

export function setTcKey(key: Buffer): void {
  if (key.length === KEY_LEN) {
    keyMaterial = key;
    return;
  }
  keyMaterial = createHash('sha256')
    .update(Buffer.from('trade-platform:tc-key-derive:v1', 'ascii'))
    .update(Buffer.from([0x00]))
    .update(key)
    .digest();
}

export function getTcKey(): Buffer {
  if (!keyMaterial) {
    throw new Error('TC anahtari ayarlanmadi');
  }
  return keyMaterial;
}

export type TcCiphertext = {
  ciphertext: Buffer;
  nonce: Buffer;
  tag: Buffer;
  keyId: string;
  cryptoVersion: string;
};

export function encryptTc(plaintext: string, keyId = 'tc-key-1'): TcCiphertext {
  const key = getTcKey();
  const nonce = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LEN });
  cipher.setAAD(AAD_CONTEXT, { plaintextLength: Buffer.byteLength(plaintext, 'utf8') });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, nonce, tag, keyId, cryptoVersion: CRYPTO_VERSION };
}

export function decryptTc(data: TcCiphertext): string {
  const key = getTcKey();
  const decipher = createDecipheriv('aes-256-gcm', key, data.nonce, { authTagLength: TAG_LEN });
  decipher.setAAD(AAD_CONTEXT, { plaintextLength: data.ciphertext.length });
  decipher.setAuthTag(data.tag);
  return Buffer.concat([decipher.update(data.ciphertext), decipher.final()]).toString('utf8');
}

export function tcFingerprint(value: string): Buffer {
  return createHash('sha256')
    .update(Buffer.from('trade-platform:tc-fingerprint:v1', 'ascii'))
    .update(Buffer.from([0x00]))
    .update(Buffer.from(value, 'utf8'))
    .digest();
}
