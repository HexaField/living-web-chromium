import { defineConfig } from '@playwright/test';

const CHROME_PATH = process.env.CHROME_PATH || '/home/josh/chromium/src/out/LivingWeb/chrome';

export default defineConfig({
  testDir: './tests',
  timeout: 60000, // Sync tests need more time
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    launchOptions: {
      executablePath: CHROME_PATH,
      args: [
        '--no-sandbox',
        '--disable-gpu',
        '--disable-dev-shm-usage',
        '--unsafely-treat-insecure-origin-as-secure=http://localhost:8080',
      ],
    },
    baseURL: 'http://localhost:8080',
    headless: true,
  },
  webServer: [
    {
      command: 'python3 -m http.server 8080 -d ./test-pages',
      port: 8080,
      reuseExistingServer: true,
    },
    {
      command: 'npx tsx ../../w3c-living-web-proposals/examples/relay/src/index.ts',
      port: 4000,
      reuseExistingServer: true,
    },
  ],
});
