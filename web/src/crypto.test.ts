import { describe, it, expect } from 'vitest';
import { aes, b64, delegate, derive, encryptItem, open, random, seal, text, unb64, itemAAD, vaultAAD } from './crypto';

describe('browser encryption boundary', () => {
  it('derives the same wrapping key for the same PRF and binds the vault to its owner', async () => {
    const prf = random();
    const one = await derive(prf.buffer);
    const two = await derive(prf.buffer);
    const raw = random();
    const box = await seal(one, raw, vaultAAD('owner'));
    expect(await open(two, box, vaultAAD('owner'))).toEqual(raw);
    await expect(open(two, box, vaultAAD('another-owner'))).rejects.toThrow();
    expect(await seal(one, raw, vaultAAD('owner'))).not.toEqual(box);
  });

  it('encrypts credentials and delegates only an item key bound to its approval request', async () => {
    const vmk = await aes(random());
    const item = await encryptItem(vmk, 'owner', 'Demo', 'fake@example.test', 'NEVER-IN-CHAT');
    expect(JSON.stringify(item)).not.toContain('NEVER-IN-CHAT');
    const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const pub = b64(await crypto.subtle.exportKey('spki', pair.publicKey));
    const envelope = await delegate(vmk, 'owner', item, pub, 'approval');
    await expect(crypto.subtle.decrypt({ name: 'RSA-OAEP', label: text.encode('wrong-approval') }, pair.privateKey, unb64(envelope))).rejects.toThrow();
    const itemKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP', label: text.encode('approval') }, pair.privateKey, unb64(envelope));
    const plain = await open(await aes(new Uint8Array(itemKey)), item.data, itemAAD('owner', item.id));
    expect(JSON.parse(new TextDecoder().decode(plain))).toEqual({ username: 'fake@example.test', password: 'NEVER-IN-CHAT' });
    await expect(delegate(vmk, 'another-owner', item, pub, 'approval')).rejects.toThrow();
  });
});
