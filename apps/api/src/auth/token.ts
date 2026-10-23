import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const PURPOSES = {
  active: 'trade-platform:auth-token-v1:active',
  remember: 'trade-platform:auth-token-v1:remember',
  reset: 'trade-platform:auth-token-v1:reset',
} as const;

export type TokenPurpose = keyof typeof PURPOSES;

export type GeneratedToken = {
  raw: string;
  hash: Buffer;
};

function digest(purpose: TokenPurpose, secret: string): Buffer {
  return createHash('sha256')
    .update(Buffer.from(PURPOSES[purpose], 'ascii'))
    .update(Buffer.from([0x00]))
    .update(Buffer.from(secret, 'utf8'))
    .digest();
}

export function generateToken(purpose: TokenPurpose): GeneratedToken {
  const raw = randomBytes(32).toString('base64url');
  return { raw, hash: digest(purpose, raw) };
}

export function tokenHash(purpose: TokenPurpose, raw: string): Buffer {
  return digest(purpose, raw);
}

export function tokenEquals(stored: Buffer, candidate: Buffer): boolean {
  if (stored.length !== candidate.length) return false;
  return timingSafeEqual(stored, candidate);
}
