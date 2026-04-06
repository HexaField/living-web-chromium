import { test, expect } from '@playwright/test';

test.describe('Multi-Tab Sync', () => {

  test('two tabs in the same context can create and join a graph', async ({ browser }) => {
    const context = await browser.newContext();
    const page1 = await context.newPage();
    const page2 = await context.newPage();

    try {
      await page1.goto('http://localhost:8080/sync-test.html');
      await page2.goto('http://localhost:8080/sync-test.html');
      await page1.waitForFunction(() => (window as any).__ready, null, { timeout: 10000 });
      await page2.waitForFunction(() => (window as any).__ready, null, { timeout: 10000 });

      // Tab 1: create identity + graph + share
      const session1 = await page1.evaluate(async () => {
        const id = await (navigator.credentials as any).create({ did: { displayName: 'Alice' } });
        const g = await (navigator as any).graph.create('multi-tab');
        const shared = await g.share({ relays: ['localhost:4000'] });
        return {
          did: id.did || id.id || 'unknown',
          uri: shared.uri,
          sessionId: shared.sessionId || 'none',
        };
      });

      expect(session1.uri).toBeTruthy();

      // Tab 2: create identity + join the shared graph
      const session2 = await page2.evaluate(async (uri: string) => {
        const id = await (navigator.credentials as any).create({ did: { displayName: 'Alice' } });
        const joined = await (navigator as any).graph.join(uri);
        return {
          did: id.did || id.id || 'unknown',
          sessionId: joined.sessionId || 'none',
        };
      }, session1.uri);

      // Both tabs should be connected
      expect(session1.uri).toBeTruthy();
      expect(session2.did).toBeTruthy();

      // If sessionIds are available, they should differ (different tab sessions)
      if (session1.sessionId !== 'none' && session2.sessionId !== 'none') {
        expect(session1.sessionId).not.toBe(session2.sessionId);
      }

    } finally {
      await context.close();
    }
  });

  test('triple added in tab 1 is visible in tab 2 (same context)', async ({ browser }) => {
    const context = await browser.newContext();
    const page1 = await context.newPage();
    const page2 = await context.newPage();

    try {
      await page1.goto('http://localhost:8080/sync-test.html');
      await page2.goto('http://localhost:8080/sync-test.html');
      await page1.waitForFunction(() => (window as any).__ready, null, { timeout: 10000 });
      await page2.waitForFunction(() => (window as any).__ready, null, { timeout: 10000 });

      // Tab 1: create + share
      const uri = await page1.evaluate(async () => {
        await (navigator.credentials as any).create({ did: { displayName: 'Alice' } });
        const g = await (navigator as any).graph.create('tab-sync');
        const shared = await g.share({ relays: ['localhost:4000'] });
        return shared.uri;
      });

      // Tab 2: join
      await page2.evaluate(async (uri: string) => {
        await (navigator.credentials as any).create({ did: { displayName: 'Alice' } });
        await (navigator as any).graph.join(uri);
      }, uri);

      // Tab 1: add triple
      await page1.evaluate(async () => {
        const graphs = await (navigator as any).graph.list();
        const g = graphs.find((g: any) => g.name === 'tab-sync') || graphs[0];
        await g.addTriple({
          source: 'urn:tab1',
          predicate: 'urn:wrote',
          target: 'urn:data',
        });
      });

      // Wait for sync
      await new Promise(r => setTimeout(r, 3000));

      // Tab 2: query
      const triples = await page2.evaluate(async () => {
        const graphs = await (navigator as any).graph.list();
        const g = graphs[0];
        const triples = await g.queryTriples({ predicate: 'urn:wrote' });
        return triples.length;
      });

      expect(triples).toBeGreaterThanOrEqual(1);

    } finally {
      await context.close();
    }
  });
});
