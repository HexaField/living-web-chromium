import { test, expect } from '@playwright/test';

test.describe('Spec 02 — Identity', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§3.1 createIdentity() returns DID with Ed25519', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const id = await (navigator as any).graph.createIdentity('TestUser');
      return { did: id.did, algorithm: id.algorithm, displayName: id.displayName };
    });
    expect(result.did).toMatch(/^did:key:z6Mk/);
    expect(result.algorithm).toBe('Ed25519');
    expect(result.displayName).toBe('TestUser');
  });

  test('§3.2 listIdentities() returns created identities', async ({ page }) => {
    const result = await page.evaluate(async () => {
      await (navigator as any).graph.createIdentity('User1');
      const list = await (navigator as any).graph.listIdentities();
      return { count: list.length, hasDid: list.every((id: any) => !!id.did) };
    });
    expect(result.count).toBeGreaterThanOrEqual(1);
    expect(result.hasDid).toBe(true);
  });

  test('§3.3 activeIdentity() returns current identity', async ({ page }) => {
    const result = await page.evaluate(async () => {
      await (navigator as any).graph.createIdentity('ActiveUser');
      const active = await (navigator as any).graph.activeIdentity();
      return { did: active.did, displayName: active.displayName };
    });
    expect(result.did).toBeTruthy();
    expect(result.displayName).toBeTruthy();
  });

  test('§3.4 setActiveIdentity() switches identity', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const id1 = await (navigator as any).graph.createIdentity('First');
      const id2 = await (navigator as any).graph.createIdentity('Second');
      await (navigator as any).graph.setActiveIdentity(id2.did);
      const active = await (navigator as any).graph.activeIdentity();
      return { activeDid: active.did, id2Did: id2.did };
    });
    expect(result.activeDid).toBe(result.id2Did);
  });
});
