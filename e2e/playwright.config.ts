import { defineConfig } from '@playwright/test';

const CHROME_PATH = process.env.CHROME_PATH || '/home/josh/chromium/src/out/LivingWeb/chrome';
const RELAY_COMMAND = process.env.RELAY_COMMAND || '';

const webServers: any[] = [
  {
    command: 'python3 -m http.server 8080 -d ./test-pages',
    port: 8080,
    reuseExistingServer: true,
  },
];

if (RELAY_COMMAND) {
  webServers.push({
    command: RELAY_COMMAND,
    port: 4000,
    reuseExistingServer: true,
  });
}

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
  webServer: webServers,
});
