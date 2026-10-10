import { test, expect } from '@playwright/test';

test('passkey registration, encrypted vault, approval, grant reuse, and revocation', async ({ page, context }) => {
  const session = await context.newCDPSession(page);
  await session.send('WebAuthn.enable', { enableUI: false });
  await session.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  const credentialBodies: string[] = [];
  const browserErrors: string[] = [];
  page.on('pageerror', error => browserErrors.push(error.message));
  page.on('request', request => { if (/\/api\/(auth|vault|approvals)\//.test(request.url()) && request.method() === 'POST') credentialBodies.push(request.postData() || ''); });

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Create a vault', exact: true })).toBeVisible();
  await page.screenshot({ path: '../artifacts/onboarding.png', fullPage: true });
  const accountName = `e2e-${Date.now().toString(36)}`;
  await page.getByLabel('Account name').fill(accountName);
  await page.getByRole('button', { name: 'Create a passkey', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Download recovery key' })).toBeVisible({ timeout: 20000 });
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download recovery key' }).click();
  await downloadPromise;

  await page.getByRole('button', { name: 'Credential vault', exact: false }).click();
  await page.getByRole('button', { name: 'Add credential', exact: true }).click();
  await page.getByLabel('Credential name').fill('Demo profile');
  await page.getByLabel('Username', { exact: true }).fill('fake@example.test');
  await page.getByLabel('Password', { exact: true }).fill('E2E-PASSWORD-NEVER-IN-CHAT');
  await page.getByRole('button', { name: 'Encrypt and save' }).click();
  await expect(page.getByRole('heading', { name: 'Demo profile' })).toBeVisible();
  expect(credentialBodies.join('\n')).not.toContain('E2E-PASSWORD-NEVER-IN-CHAT');
  expect(credentialBodies.join('\n')).not.toContain('results');

  await page.getByRole('button', { name: 'Use with agent' }).click();
  await page.getByLabel('Requested access duration').selectOption('60');
  await page.getByRole('button', { name: 'Read my demo profile' }).click();
  await expect(page.getByRole('link', { name: 'Review access request' })).toBeVisible();
  await expect(page.getByText('Signed in as', { exact: false })).toHaveCount(0);
  await page.getByRole('link', { name: 'Review access request' }).click();
  await expect(page.getByRole('heading', { name: 'Approve credential access' })).toBeVisible();
  await expect(page.getByText('1 minute', { exact: true })).toBeVisible();
  await page.screenshot({ path: '../artifacts/approval.png', fullPage: true });
  await page.getByRole('button', { name: 'Approve with passkey' }).click();
  await expect(page.getByText('Signed in as fake@example.test.', { exact: false })).toBeVisible({ timeout: 20000 });
  expect(await page.locator('body').innerText()).not.toContain('E2E-PASSWORD-NEVER-IN-CHAT');
  const state = await page.evaluate(async () => (await fetch('/api/state')).json());
  expect(state.grants[0].uses).toBe(1);
  expect(JSON.stringify(state)).not.toContain('delegatedKey');
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect(page.getByText('Existing grant used', { exact: false })).toBeVisible();
  await page.screenshot({ path: '../artifacts/chat.png', fullPage: true });

  await page.getByRole('button', { name: 'Revoke access', exact: true }).click();
  await expect(page.getByText('No access granted', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect(page.getByRole('link', { name: 'Review access request' })).toHaveCount(2);

  await page.reload();
  await expect(page.getByText('Vault locked', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByText('Vault unlocked', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Credential vault', exact: false }).click();
  await expect(page.getByRole('heading', { name: 'Demo profile' })).toBeVisible();
  await page.screenshot({ path: '../artifacts/vault.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('heading', { name: 'Credential vault', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: '../artifacts/mobile-vault.png', fullPage: true });
  expect(browserErrors).toEqual([]);
});
