import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 60000,
  expect: { timeout: 10000 },
  use: { baseURL: process.env.BASE_URL || 'http://localhost:5173', viewport: { width: 1360, height: 900 }, screenshot: 'only-on-failure', trace: 'off' },
  reporter: 'list',
  workers: 1,
});
