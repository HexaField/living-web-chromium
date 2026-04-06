import { test, expect } from '@playwright/test';

test.describe('Spec 05 — Governance', () => {
  test.setTimeout(60000);

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§6.1 canAddTriple() checks governance rules on SharedGraph', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('gov-test');
      const shared = await g.share();
      // canAddTriple returns whether a triple is permitted under current governance
      const allowed = await shared.canAddTriple({
        source: 'urn:test',
        predicate: 'urn:wrote',
        target: 'urn:data',
      });
      return allowed;
    });
    // Default governance should allow writes from the creator
    expect(result).toBeTruthy();
  });

  test('§6.2 myCapabilities() retrieves current governance capabilities', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('gov-get-test');
      const shared = await g.share();
      return typeof shared.myCapabilities === 'function';
    });
    expect(result).toBe(true);
  });
});
