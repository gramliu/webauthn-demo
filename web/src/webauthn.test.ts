import { it, expect, vi } from 'vitest';
import { runInNewContext } from 'node:vm';
import { prfBytes, serialize } from './webauthn';
import { b64, derive, open, seal, text, vaultAAD } from './crypto';

it('normalizes native, cross-realm, sliced, and JSON PRF results without changing vault keys', async () => {
  const raw = Uint8Array.from({ length: 32 }, (_, i) => (i * 17 + 251) % 256);
  const expected = raw.slice();
  const standardBase64 = btoa(String.fromCharCode(...raw));
  expect(standardBase64).toMatch(/[+/]/);
  const padded = new Uint8Array(40);
  padded.set(raw, 4);
  const variants = [
    raw.buffer,
    runInNewContext('Uint8Array.from({ length: 32 }, (_, i) => (i * 17 + 251) % 256).buffer'),
    new Uint8Array(padded.buffer, 4, 32),
    new DataView(padded.buffer, 4, 32),
    b64(raw),
    b64(raw) + '=',
    standardBase64,
    standardBase64.replace(/=+$/, ''),
  ];
  const originalKey = await derive(raw.buffer);
  const existingVault = await seal(originalKey, text.encode('existing encrypted vault'), vaultAAD('owner'));
  // Reproduce the reported browser error with serialized PRF output.
  await expect(crypto.subtle.importKey('raw', b64(raw) as unknown as ArrayBuffer, 'HKDF', false, ['deriveKey'])).rejects.toThrow();
  for (const value of variants) {
    const normalized = prfBytes(value)!;
    expect(new Uint8Array(normalized)).toEqual(raw);
    const recovered = await open(await derive(normalized), existingVault, vaultAAD('owner'));
    expect(new TextDecoder().decode(recovered)).toBe('existing encrypted vault');
    new Uint8Array(normalized).fill(0);
    expect(raw).toEqual(expected); // Zeroing the working copy never alters native output.
  }
});

it('rejects missing, malformed, and incorrectly sized PRF output safely', () => {
  expect(prfBytes(undefined)).toBeUndefined();
  expect(prfBytes(null)).toBeUndefined();
  for (const value of [{}, [], 'not-a-key', new ArrayBuffer(31), new ArrayBuffer(33), b64(new Uint8Array(31))]) {
    expect(() => prfBytes(value)).toThrow(/passkey returned/i);
  }
});

it('never serializes PRF secret bytes into an authentication request', () => {
  vi.stubGlobal('AuthenticatorAttestationResponse', class {});
  const bytes = new Uint8Array([1, 2, 3]).buffer;
  const credential = {
    id: 'credential', rawId: bytes, type: 'public-key', authenticatorAttachment: 'platform',
    response: { clientDataJSON: bytes, authenticatorData: bytes, signature: bytes, userHandle: bytes },
    getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: new TextEncoder().encode('PRF-SECRET-MUST-STAY-LOCAL').buffer } } }),
  } as unknown as PublicKeyCredential;
  const serialized = serialize(credential);
  expect(serialized.clientExtensionResults).toEqual({ prf: { enabled: true } });
  expect(JSON.stringify(serialized)).not.toContain('results');
  expect(JSON.stringify(serialized)).not.toContain('PRF-SECRET');
  vi.unstubAllGlobals();
});
