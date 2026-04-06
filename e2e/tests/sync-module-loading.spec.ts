import { test, expect } from '@playwright/test';

test.describe('WASM Module Loading', () => {

  test('polyfill exposes navigator.graph after loading', async ({ page }) => {
    await page.goto('http://localhost:8080/sync-test.html');
    await page.waitForFunction(() => (window as any).navigator?.graph, null, { timeout: 10000 });

    const hasGraph = await page.evaluate(() => {
      return typeof (navigator as any).graph !== 'undefined';
    });

    expect(hasGraph).toBe(true);
  });

  test('navigator.graph.create returns a graph object', async ({ page }) => {
    await page.goto('http://localhost:8080/sync-test.html');
    await page.waitForFunction(() => (window as any).navigator?.graph, null, { timeout: 10000 });

    const result = await page.evaluate(async () => {
      try {
        await (navigator as any).graph.createIdentity('Tester');
        const g = await (navigator as any).graph.create('module-test');
        return { success: true, name: g.name || 'unknown' };
      } catch (e: any) {
        return { success: false, error: e.message };
      }
    });

    expect(result.success).toBe(true);
  });

  test('module loader rejects tampered content hash', async ({ page }) => {
    await page.goto('http://localhost:8080/sync-test.html');
    await page.waitForFunction(() => (window as any).navigator?.graph, null, { timeout: 10000 });

    const result = await page.evaluate(async () => {
      try {
        // Attempt to load a sync module with a deliberately wrong hash
        const g = await (navigator as any).graph.create('hash-test');
        await g.loadModule('http://localhost:8080/polyfill-bundle.js', {
          expectedHash: 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        });
        return 'should have thrown';
      } catch (e: any) {
        return e.message;
      }
    });

    // Should reject due to hash mismatch
    expect(result).not.toBe('should have thrown');
  });

  test('share() returns a URI containing graph identifier', async ({ page }) => {
    await page.goto('http://localhost:8080/sync-test.html');
    await page.waitForFunction(() => (window as any).navigator?.graph, null, { timeout: 10000 });

    const uri = await page.evaluate(async () => {
      await (navigator as any).graph.createIdentity('Sharer');
      const g = await (navigator as any).graph.create('uri-test');
      const shared = await g.share({ relays: ['localhost:4000'] });
      return shared.uri;
    });

    expect(uri).toBeTruthy();
    expect(typeof uri).toBe('string');
  });
});
