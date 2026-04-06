import { test, expect } from '@playwright/test';

test.describe('Spec 05 — Governance', () => {
  test.setTimeout(60000);

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§6.1 canAddTriple() checks governance rules on SharedGraph', async ({ page }) => {
    page.on('console', msg => console.log('PAGE:', msg.text()));
    const result = await page.evaluate(async () => {
      console.log('step1: creating graph');
      const g = await (navigator as any).graph.create('gov-test');
      console.log('step2: sharing graph');
      const shared = await g.share();
      console.log('step3: shared=', typeof shared, 'canAddTriple=', typeof shared.canAddTriple);
      
      // Try with a race against a timeout to see if promise is stuck
      const timeout = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('canAddTriple timed out after 10s')), 10000));
      
      try {
        const allowed = await Promise.race([
          shared.canAddTriple({
            source: 'urn:test',
            predicate: 'urn:wrote',
            target: 'urn:data',
          }),
          timeout
        ]);
        console.log('step4: allowed=', JSON.stringify(allowed));
        return allowed;
      } catch (e: any) {
        console.log('step4-error:', e.message);
        // Try calling peers() to see if shared_host_ pipe works at all
        try {
          const peers = await shared.peers();
          console.log('step5: peers() works:', JSON.stringify(peers));
        } catch (e2: any) {
          console.log('step5: peers() also failed:', e2.message);
        }
        throw e;
      }
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
