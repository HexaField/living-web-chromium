import { test, expect } from '@playwright/test';

test.describe('Spec 03 — Graph Sync (SharedGraph)', () => {
  // share() depends on SyncService connectivity — use longer timeout
  test.setTimeout(60000);

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§5.1 share() returns SharedGraph with uri', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('sync-test');
      await g.addTriple({ source: 'urn:a', predicate: 'urn:b', target: 'urn:c' });
      const shared = await g.share();
      return {
        uri: shared.uri,
        hasUri: !!shared.uri,
        hasModuleHash: !!shared.moduleHash,
        hasSetGovernance: typeof shared.setGovernance === 'function',
      };
    });
    expect(result.hasUri).toBe(true);
    expect(result.uri).toBeTruthy();
  });

  test('§5.2 join() connects to a shared graph by URI', async ({ page }) => {
    test.skip(true, 'Requires second browser context or peer — skipped for single-instance CI');
  });

  test('§5.3 shared graph propagates triples', async ({ page }) => {
    test.skip(true, 'Requires two peers — skipped for single-instance CI');
  });
});
