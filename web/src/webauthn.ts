import { b64, unb64 } from './crypto';
import type { Ceremony } from './types';

type Extensions = { prf?: { enabled?: boolean; results?: { first: unknown } } };
type DescriptorJSON = Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string };

// Native APIs return BufferSource; WebAuthn JSON/embedded-browser bridges can
// return base64url. Copy into this realm's ArrayBuffer before using Web Crypto.
// Keep the bytes client-side and preserve the exact key material for old vaults.
export function prfBytes(value: unknown): ArrayBuffer | undefined {
  if (value === undefined || value === null) return undefined;
  let bytes: Uint8Array;
  if (typeof value === 'string' && /^[A-Za-z0-9+/_-]{43}=?$/.test(value)) {
    bytes = unb64(value);
  } else if (ArrayBuffer.isView(value)) {
    bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  } else if (Object.prototype.toString.call(value) === '[object ArrayBuffer]') {
    bytes = new Uint8Array(value as ArrayBuffer);
  } else {
    throw new Error('The passkey returned an unsupported encryption-key format. Try this site in your usual browser.');
  }
  if (bytes.byteLength !== 32) {
    throw new Error('The passkey returned an invalid encryption key. Try this site in your usual browser.');
  }
  return Uint8Array.from(bytes).buffer;
}

function supported() {
  if (!window.isSecureContext || !navigator.credentials || typeof PublicKeyCredential === 'undefined') {
    throw new Error('Passkeys need HTTPS or localhost and a supported browser.');
  }
}
function descriptors(value: unknown): PublicKeyCredentialDescriptor[] {
  return ((value || []) as DescriptorJSON[]).map(item => ({ ...item, id: unb64(item.id) }));
}
export function serialize(credential: PublicKeyCredential) {
  const response = credential.response;
  const results = credential.getClientExtensionResults() as Extensions;
  // PRF result bytes MUST stay in the browser. Never use credential.toJSON(),
  // which can include those bytes in clientExtensionResults.
  const clientExtensionResults = results.prf?.enabled !== undefined ? { prf: { enabled: results.prf.enabled } } : {};
  const basic = { id: credential.id, rawId: b64(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults };
  if (response instanceof AuthenticatorAttestationResponse) {
    return { ...basic, response: { clientDataJSON: b64(response.clientDataJSON), attestationObject: b64(response.attestationObject), transports: response.getTransports() } };
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return { ...basic, response: { clientDataJSON: b64(assertion.clientDataJSON), authenticatorData: b64(assertion.authenticatorData), signature: b64(assertion.signature), userHandle: assertion.userHandle ? b64(assertion.userHandle) : null } };
}
export async function createPasskey(ceremony: Ceremony) {
  supported();
  const data = ceremony.publicKey;
  const user = data.user as { id: string; name: string; displayName: string };
  const publicKey = { ...data, challenge: unb64(data.challenge as string), user: { ...user, id: unb64(user.id) }, excludeCredentials: descriptors(data.excludeCredentials), extensions: { prf: {} } } as unknown as PublicKeyCredentialCreationOptions;
  const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential | null;
  if (!credential) throw new Error('Passkey registration was cancelled.');
  return serialize(credential);
}
export async function authenticate(ceremony: Ceremony) {
  supported();
  const data = ceremony.publicKey;
  const publicKey = { ...data, challenge: unb64(data.challenge as string), allowCredentials: descriptors(data.allowCredentials), extensions: { prf: { eval: { first: unb64(ceremony.salt) } } } } as unknown as PublicKeyCredentialRequestOptions;
  const credential = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
  if (!credential) throw new Error('Passkey verification was cancelled.');
  const prf = prfBytes((credential.getClientExtensionResults() as Extensions).prf?.results?.first);
  return { credential: serialize(credential), prf };
}
