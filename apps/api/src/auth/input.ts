const WHITESPACE_TRIM = /[\s\u200B\uFEFF]+/g;

export function normalizeEmailKey(email: string): string {
  const trimmed = email.replace(WHITESPACE_TRIM, '');
  return trimmed.toLowerCase();
}

export function isValidTcKimlik(tc: string): boolean {
  if (!/^\d{11}$/.test(tc)) return false;

  const digits = tc.split('').map(Number);
  const oddSum = digits[0]! + digits[2]! + digits[4]! + digits[6]! + digits[8]!;
  const evenSum = digits[1]! + digits[3]! + digits[5]! + digits[7]!;

  const check1 = (oddSum * 7 - evenSum) % 10;
  const check2 = (oddSum + evenSum + check1) % 10;

  if (check1 !== digits[9]) return false;
  if (check2 !== digits[10]) return false;
  if (digits[0] === 0) return false;

  return true;
}

export function passwordScalarCount(password: string): number {
  return Array.from(password).length;
}
