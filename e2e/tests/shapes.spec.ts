import { test, expect } from '@playwright/test';

test.describe('Spec 04 — Shapes (SHACL)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('§5.1 addShape() registers a shape', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('shape-test');
      await g.addShape('Task', JSON.stringify({
        targetClass: 'urn:Task',
        properties: [{ name: 'title', path: 'urn:title', datatype: 'string' }],
        constructor: [{ action: 'setSingleTarget', source: 'this', predicate: 'urn:title', target: 'title' }],
      }));
      const shapes = await g.getShapes();
      return shapes;
    });
    expect(result).toContain('Task');
  });

  test('§5.2 getShapes() returns registered shape names', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('shapes-list-test');
      await g.addShape('Person', JSON.stringify({
        targetClass: 'urn:Person',
        properties: [{ name: 'name', path: 'urn:name', datatype: 'string' }],
        constructor: [{ action: 'setSingleTarget', source: 'this', predicate: 'urn:name', target: 'name' }],
      }));
      await g.addShape('Note', JSON.stringify({
        targetClass: 'urn:Note',
        properties: [{ name: 'body', path: 'urn:body', datatype: 'string' }],
        constructor: [{ action: 'setSingleTarget', source: 'this', predicate: 'urn:body', target: 'body' }],
      }));
      return g.getShapes();
    });
    expect(result).toContain('Person');
    expect(result).toContain('Note');
  });

  test('§5.3 removeShape() unregisters a shape', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const g = await (navigator as any).graph.create('shape-remove-test');
      await g.addShape('Temp', JSON.stringify({
        targetClass: 'urn:Temp',
        properties: [],
        constructor: [],
      }));
      let shapes = await g.getShapes();
      const hadIt = shapes.includes('Temp');
      await g.removeShape('Temp');
      shapes = await g.getShapes();
      return { hadIt, hasItAfter: shapes.includes('Temp') };
    });
    expect(result.hadIt).toBe(true);
    expect(result.hasItAfter).toBe(false);
  });
});
