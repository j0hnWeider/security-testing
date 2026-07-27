import { defineConfig } from '@playwright/test';
import dotenv from 'dotenv';
dotenv.config();

export default defineConfig({
  testDir: './src/tests',
  timeout: 60000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 4 : undefined,

  reporter: [
    ['html', { outputFolder: 'reports/playwright-report' }],
    ['list'],
    ['allure-playwright', { outputFolder: 'allure-results' }]
  ],

  outputDir: 'test-results',

  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    baseURL: process.env.API_BASE_URL || 'https://serverest.dev',
    extraHTTPHeaders: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  },

  projects: [
    {
      name: 'security',
      testMatch: /.*\.spec\.ts/,
    },
  ],
});
