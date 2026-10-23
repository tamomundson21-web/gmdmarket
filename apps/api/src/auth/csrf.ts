import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const CSRF_SECRET = () => process.env.F1_CSRF_SECRET ?? 'dev-csrf-secret-change-me';

export function allowedOrigin(origin: string | undefined): boolean {
  if (!origin) return false;
  const allowed = (process.env.ALLOWED_ORIGINS ?? 'http://localhost:3000')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  return allowed.includes(origin);
}

export function generateCsrf(): { token: string; cookie: string } {
  const id = randomBytes(16).toString('hex');
  const secret = randomBytes(32).toString('base64url');
  const token = `${id}.${secret}`;
  const sig = createHmac('sha256', CSRF_SECRET())
    .update(Buffer.from(token, 'utf8'))
    .digest('base64url');
  return { token, cookie: `${token}.${sig}` };
}

export function verifyCsrf(cookieValue: string | undefined, headerValue: string | undefined): boolean {
  if (!cookieValue || !headerValue) return false;
  const parts = cookieValue.split('.');
  if (parts.length !== 3) return false;
  const [id, secret, sig] = parts;
  if (!id || !secret || !sig) return false;

  const token = `${id}.${secret}`;
  const expected = createHmac('sha256', CSRF_SECRET())
    .update(Buffer.from(token, 'utf8'))
    .digest('base64url');

  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;

  const header = headerValue.trim();
  return timingSafeEqual(Buffer.from(header), Buffer.from(token));
}
