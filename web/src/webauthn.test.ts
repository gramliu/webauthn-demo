import { it, expect, vi } from 'vitest';
import { serialize } from './webauthn';

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
