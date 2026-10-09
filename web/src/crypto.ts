import type { Box, Item } from './types';

export const text = new TextEncoder();
export function b64(bytes: ArrayBuffer | Uint8Array): string {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return btoa(String.fromCharCode(...data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
export const random = () => crypto.getRandomValues(new Uint8Array(32));
export async function aes(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function derive(prf: ArrayBuffer): Promise<CryptoKey> {
  const input = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: text.encode('keyhold-v1'), info: text.encode('vault-key-wrapper') }, input, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function seal(key: CryptoKey, data: Uint8Array<ArrayBuffer>, aad: string): Promise<Box> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: text.encode(aad) }, key, data);
  return { nonce: b64(nonce), ciphertext: b64(ciphertext) };
}
export async function open(key: CryptoKey, box: Box, aad: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.nonce), additionalData: text.encode(aad) }, key, unb64(box.ciphertext)));
}
export const vaultAAD = (account: string) => `vault:${account}:1`;
export const itemAAD = (account: string, item: string) => `credential:${account}:${item}:1`;
export const keyAAD = (account: string, item: string) => `item-key:${account}:${item}:1`;
export async function encryptItem(vault: CryptoKey, account: string, label: string, username: string, password: string): Promise<Item> {
  const id = b64(random());
  const raw = random();
  try {
    const key = await aes(raw);
    const plain = text.encode(JSON.stringify({ username, password }));
    try {
      return { id, label, version: 1, data: await seal(key, plain, itemAAD(account, id)), wrappedKey: await seal(vault, raw, keyAAD(account, id)), createdAt: new Date().toISOString() };
    } finally { plain.fill(0); }
  } finally { raw.fill(0); }
}
export async function delegate(vault: CryptoKey, account: string, item: Item, publicKey: string, approvalId: string): Promise<string> {
  const raw = await open(vault, item.wrappedKey, keyAAD(account, item.id));
  try {
    const recipient = await crypto.subtle.importKey('spki', unb64(publicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    return b64(await crypto.subtle.encrypt({ name: 'RSA-OAEP', label: text.encode(approvalId) }, recipient, raw));
  } finally { raw.fill(0); }
}
