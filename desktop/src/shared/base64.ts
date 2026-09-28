// One owner of Base64 for the window: strict alphabet, URL-safe spelling and padding rules.
const fail = (code: string): never => {
  throw new Error(code);
};

/** Decodes standard or URL-safe Base64 (whitespace ignored, padding optional) to bytes. */
export function decodeBytes(value: string): Uint8Array {
  const cleaned = value.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleaned) || cleaned.replace(/=/g, '').length % 4 === 1)
    return fail('invalid_base64');
  try {
    return Uint8Array.from(atob(cleaned), (c) => c.charCodeAt(0));
  } catch {
    return fail('invalid_base64');
  }
}

/** Encodes bytes as standard Base64 with padding. */
export function encodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}

/** Decodes Base64 of UTF-8 text; invalid UTF-8 is an `invalid_base64` error. */
export function decodeText(value: string): string {
  const bytes = decodeBytes(value);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return fail('invalid_base64');
  }
}

/** Encodes UTF-8 text as standard Base64, or as unpadded URL-safe Base64. */
export function encodeText(text: string, urlSafe = false): string {
  const encoded = encodeBytes(new TextEncoder().encode(text));
  return urlSafe ? encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : encoded;
}
