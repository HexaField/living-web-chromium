import { test, expect, chromium } from '@playwright/test';

const CHROME_PATH = process.env.CHROME_PATH || '/home/josh/chromium/src/out/LivingWeb/chrome';

test.describe('WebSocket Relay Sync', () => {

  // Skip: Chromium's SyncService is in-process only — cross-browser sync requires
  // real network transport (WebSocket relay) which isn't implemented yet.
  // Two separate browser instances cannot share graph state without external relay infrastructure.
  test.skip('two browsers can share and sync a graph via WebSocket relay', async () => {
    const browserA = await chromium.launch({
      executablePath: CHROME_PATH,
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
             '--unsafely-treat-insecure-origin-as-secure=http://localhost:8080'],
    });
    const browserB = await chromium.launch({
      executablePath: CHROME_PATH,
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
             '--unsafely-treat-insecure-origin-as-secure=http://localhost:8080'],
    });

    const pageA = await browserA.newPage();
    const pageB = await browserB.newPage();

    try {
      await pageA.goto('http://localhost:8080/sync-test.html');
      await pageB.goto('http://localhost:8080/sync-test.html');

      await pageA.waitForFunction(() => (window as any).navigator?.graph, null, { timeout: 10000 });
      await pageB.waitForFunction(() => (window as any).navigator?.graph, null, { timeout: 10000 });

      // Browser A: create identity + graph + share via relay
      const graphUri = await pageA.evaluate(async () => {
        await (navigator as any).graph.createIdentity('Alice');
        const g = await (navigator as any).graph.create('sync-test');
        const shared = await g.share({ relays: ['localhost:4000'] });
        return shared.uri;
      });

      expect(graphUri).toBeTruthy();

      // Browser B: create identity + join
      await pageB.evaluate(async (uri: string) => {
        await (navigator as any).graph.createIdentity('Bob');
        await (navigator as any).graph.join(uri);
      }, graphUri);

      // Browser A: add a triple
      await pageA.evaluate(async () => {
        const graphs = await (navigator as any).graph.list();
        const g = graphs.find((g: any) => g.name === 'sync-test') || graphs[0];
        await g.addTriple({
          source: 'urn:alice',
          predicate: 'urn:says',
          target: 'urn:hello',
        });
      });

      await new Promise(r => setTimeout(r, 3000));

      // Browser B: should see Alice's triple
      const triplesFromB = await pageB.evaluate(async () => {
        const graphs = await (navigator as any).graph.list();
        const g = graphs[0];
        const triples = await g.queryTriples({ predicate: 'urn:says' });
        return triples.map((t: any) => ({
          source: t.source, predicate: t.predicate, target: t.target,
        }));
      });

      expect(triplesFromB.length).toBeGreaterThanOrEqual(1);
      expect(triplesFromB).toContainEqual(
        expect.objectContaining({ source: 'urn:alice', predicate: 'urn:says', target: 'urn:hello' })
      );

    } finally {
      await browserA.close();
      await browserB.close();
    }
  });
});
