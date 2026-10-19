import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

const PREFIX = Buffer.from('trade-platform:f1-request:v1', 'utf8');
const SEPARATOR = Buffer.from([0x00]);
const ACCEPT_WINDOW_MS = 15 * 60 * 1000;

let fingerprintKey: Buffer | null = null;

export function setFingerprintKey(key: Buffer): void {
  fingerprintKey = key;
}

export function getFingerprintKeyId(): string {
  return process.env.F1_FINGERPRINT_KEY_ID ?? 'v1';
}

type EnvelopeInput = {
  action: string;
  commandKey: string;
  installationId: string;
  targetUserId: string | null;
  actorId: string | null;
  operationGeneration: bigint;
  keyId: string;
};

export type Envelope = {
  envelopeId: string;
  commandKey: string;
  installationId: string;
  targetUserId: string | null;
  actorId: string | null;
  action: string;
  operationGeneration: bigint;
  keyId: string;
  issuedAt: Date;
  acceptUntil: Date;
  fingerprint: Buffer;
};

function hmac(key: Buffer, data: Buffer): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

function canonicalString(parts: string[]): string {
  return JSON.stringify(parts);
}

export function createEnvelope(input: EnvelopeInput): Envelope {
  if (!fingerprintKey) throw new Error('fingerprint key ayarlanmadi');

  const issuedAt = new Date();
  const acceptUntil = new Date(issuedAt.getTime() + ACCEPT_WINDOW_MS);

  const canonical = canonicalString([
    input.action,
    input.commandKey,
    input.installationId,
    input.targetUserId ?? '',
    input.actorId ?? '',
    input.operationGeneration.toString(),
    input.keyId,
  ]);

  const fingerprint = hmac(
    Buffer.concat([PREFIX, SEPARATOR, Buffer.from(canonical, 'utf8')]),
    fingerprintKey,
  );

  return {
    envelopeId: randomUUID(),
    commandKey: input.commandKey,
    installationId: input.installationId,
    targetUserId: input.targetUserId ?? null,
    actorId: input.actorId ?? null,
    action: input.action,
    operationGeneration: input.operationGeneration,
    keyId: input.keyId,
    issuedAt,
    acceptUntil,
    fingerprint,
  };
}

export function verifyFingerprint(
  envelope: Omit<Envelope, 'fingerprint' | 'envelopeId' | 'issuedAt' | 'acceptUntil'>,
  fingerprint: Buffer,
): boolean {
  if (!fingerprintKey) throw new Error('fingerprint key ayarlanmadi');

  const canonical = canonicalString([
    envelope.action,
    envelope.commandKey,
    envelope.installationId,
    envelope.targetUserId ?? '',
    envelope.actorId ?? '',
    envelope.operationGeneration.toString(),
    envelope.keyId,
  ]);

  const expected = hmac(
    Buffer.concat([PREFIX, SEPARATOR, Buffer.from(canonical, 'utf8')]),
    fingerprintKey,
  );

  return timingSafeEqual(expected, fingerprint);
}

export function isEnvelopeExpired(
  envelope: { acceptUntil: Date },
  now: Date = new Date(),
): boolean {
  return now.getTime() > envelope.acceptUntil.getTime();
}
