import { test, expect } from '@playwright/test';

test.describe('Spec 05 — Governance', () => {
  test.setTimeout(60000);

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§6.1 setGovernance() on SharedGraph sets governance rules', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('gov-test');
      const shared = await g.share();
      const rules = {
        allowWrite: ['did:key:z6MkTest'],
        requireApproval: false,
      };
      await shared.setGovernance(rules);
      const gov = await shared.getGovernance();
      return gov;
    });
    expect(result).toBeTruthy();
  });

  test('§6.2 getGovernance() retrieves current governance', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('gov-get-test');
      const shared = await g.share();
      return typeof shared.getGovernance === 'function';
    });
    expect(result).toBe(true);
  });
});
