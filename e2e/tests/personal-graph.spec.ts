import { test, expect } from '@playwright/test';
import { ensureGraphAPI } from '../helpers/setup';

test.describe('Spec 01 — PersonalGraph', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§4.1 navigator.graph MUST exist', async ({ page }) => {
    await ensureGraphAPI(page);
  });

  test('§4.1 create() MUST return a PersonalGraph with uuid', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('test');
      return {
        uuid: g.uuid,
        name: g.name,
        hasAddTriple: typeof g.addTriple === 'function',
        hasQueryTriples: typeof g.queryTriples === 'function',
        hasQuerySparql: typeof g.querySparql === 'function',
        hasSnapshot: typeof g.snapshot === 'function',
      };
    });
    expect(result.uuid).toBeTruthy();
    expect(result.name).toBe('test');
    expect(result.hasAddTriple).toBe(true);
    expect(result.hasQueryTriples).toBe(true);
    expect(result.hasQuerySparql).toBe(true);
    expect(result.hasSnapshot).toBe(true);
  });

  test('§4.2 addTriple() stores and queryTriples() retrieves', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('triple-test');
      await g.addTriple({ source: 'urn:a', predicate: 'urn:knows', target: 'urn:b' });
      const triples = await g.queryTriples({ predicate: 'urn:knows' });
      return { count: triples.length, first: triples[0] };
    });
    expect(result.count).toBe(1);
    expect(result.first.source ?? result.first.data?.source).toBeTruthy();
  });

  test('§4.2 removeTriple() deletes a triple', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('remove-triple-test');
      await g.addTriple({ source: 'urn:x', predicate: 'urn:p', target: 'urn:y' });
      let triples = await g.queryTriples({ predicate: 'urn:p' });
      const before = triples.length;
      await g.removeTriple({ source: 'urn:x', predicate: 'urn:p', target: 'urn:y' });
      triples = await g.queryTriples({ predicate: 'urn:p' });
      return { before, after: triples.length };
    });
    expect(result.before).toBe(1);
    expect(result.after).toBe(0);
  });

  test('§4.3 querySparql() returns results', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('sparql-test');
      await g.addTriple({ source: 'urn:alice', predicate: 'urn:knows', target: 'urn:bob' });
      return g.querySparql('SELECT ?s ?o WHERE { ?s <urn:knows> ?o }');
    });
    expect(result.length).toBeGreaterThan(0);
  });

  test('§4.4 snapshot() returns all triples', async ({ page }) => {
    const count = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('snap-test');
      await g.addTriple({ source: 'urn:x', predicate: 'urn:y', target: 'urn:z' });
      const all = await g.snapshot();
      return all.length;
    });
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('§4.5 list() returns created graphs', async ({ page }) => {
    const result = await page.evaluate(async () => {
      await (navigator as any).graph.create('list-test-1');
      await (navigator as any).graph.create('list-test-2');
      const list = await (navigator as any).graph.list();
      return list.length;
    });
    expect(result).toBeGreaterThanOrEqual(2);
  });

  test('§4.6 remove() deletes a graph', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('remove-test');
      return (navigator as any).graph.remove(g.uuid);
    });
    expect(result).toBe(true);
  });

  test('§4.6 get() retrieves a graph by uuid', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('get-test');
      const retrieved = await (navigator as any).graph.get(g.uuid);
      return { uuid: retrieved.uuid, name: retrieved.name };
    });
    expect(result.uuid).toBeTruthy();
    expect(result.name).toBe('get-test');
  });

  test('§6.1 graph data persists across page navigations', async ({ page }) => {
    await page.goto('/');
    // Create graph + add triple
    const uuid = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('persist-test');
      await g.addTriple({ source: 'urn:a', predicate: 'urn:b', target: 'urn:c' });
      return g.uuid;
    });
    // Navigate away
    await page.goto('about:blank');
    // Navigate back
    await page.goto('/');
    // Get the graph and check triple still there
    const count = await page.evaluate(async (uuid) => {
      const g = await (navigator as any).graph.get(uuid);
      const triples = await g.queryTriples({});
      return triples.length;
    }, uuid);
    expect(count).toBeGreaterThanOrEqual(1);
  });
});
