import { test, expect } from '@playwright/test';

test.describe('Spec 05 — Governance', () => {
  test.setTimeout(60000);

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§6.1 canAddTriple() checks governance rules on SharedGraph', async ({ page }) => {
    page.on('console', msg => console.log('PAGE:', msg.text()));
    page.on('crash', () => console.log('PAGE CRASHED!'));
    page.on('pageerror', (err) => console.log('PAGE ERROR:', err.message));
    
    const result = await page.evaluate(async () => {
      console.log('step1: creating graph');
      const g = await (navigator as any).graph.create('gov-test');
      console.log('step2: sharing graph');
      const shared = await g.share();
      console.log('step3: calling canAddTriple');
      
      const allowed = await shared.canAddTriple({
        source: 'urn:test',
        predicate: 'urn:wrote',
        target: 'urn:data',
      });
      console.log('step4: allowed=', JSON.stringify(allowed));
      return allowed;
    });
    expect(result).toBeTruthy();
  });

  test('§6.2 myCapabilities() retrieves current governance capabilities', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('gov-get-test');
      const shared = await g.share();
      const caps = await shared.myCapabilities();
      return caps;
    });
    expect(result).toBeTruthy();
  });
});
