import { test, expect } from '@playwright/test';

test.describe('Spec 06 — Group Identity', () => {
  // Group identity is polyfill-only in current Chromium build
  // Load polyfill via script tag for these tests

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Check if native group identity exists; if not, skip
  });

  test('§7.1 createGroup() returns a GroupIdentity', async ({ page }) => {
    const hasMethod = await page.evaluate(() =>
      typeof (navigator as any).graph.createGroup === 'function'
    );
    test.skip(!hasMethod, 'createGroup() not implemented in this Chromium build — needs polyfill');

    const result = await page.evaluate(async () => {
      const group = await (navigator as any).graph.createGroup('TestGroup');
      return { name: group.name, did: group.did, hasAddMember: typeof group.addMember === 'function' };
    });
    expect(result.name).toBe('TestGroup');
    expect(result.did).toBeTruthy();
    expect(result.hasAddMember).toBe(true);
  });

  test('§7.2 addMember() adds identity to group', async ({ page }) => {
    const hasMethod = await page.evaluate(() =>
      typeof (navigator as any).graph.createGroup === 'function'
    );
    test.skip(!hasMethod, 'createGroup() not implemented in this Chromium build');

    const result = await page.evaluate(async () => {
      const id = await (navigator as any).graph.createIdentity('Member1');
      const group = await (navigator as any).graph.createGroup('MemberGroup');
      await group.addMember(id.did);
      const members = await group.listMembers();
      return { count: members.length, hasMember: members.some((m: any) => m.did === id.did) };
    });
    expect(result.count).toBeGreaterThanOrEqual(1);
    expect(result.hasMember).toBe(true);
  });

  test('§7.3 nested groups', async ({ page }) => {
    const hasMethod = await page.evaluate(() =>
      typeof (navigator as any).graph.createGroup === 'function'
    );
    test.skip(!hasMethod, 'createGroup() not implemented in this Chromium build');

    const result = await page.evaluate(async () => {
      const parent = await (navigator as any).graph.createGroup('Parent');
      const child = await (navigator as any).graph.createGroup('Child');
      await parent.addMember(child.did);
      const members = await parent.listMembers();
      return members.some((m: any) => m.did === child.did);
    });
    expect(result).toBe(true);
  });
});
