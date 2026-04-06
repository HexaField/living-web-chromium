import { Page, expect } from '@playwright/test';

/**
 * Assert that navigator.graph exists (Living Web Chromium API).
 */
export async function ensureGraphAPI(page: Page) {
  const hasGraph = await page.evaluate(() => 'graph' in navigator);
  expect(hasGraph).toBe(true);
}

/**
 * Evaluate an async function body in the browser context.
 */
export async function evaluate<T = any>(page: Page, fn: string): Promise<T> {
  return page.evaluate(`(async () => { ${fn} })()`) as Promise<T>;
}
