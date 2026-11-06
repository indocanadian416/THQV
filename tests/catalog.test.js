'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { defenderCatalog, crowdstrikeCatalog } = require('../js/catalog.js');

for (const [label, catalog, count] of [['Defender', defenderCatalog, 6], ['CrowdStrike', crowdstrikeCatalog, 7]]) {
  test(`${label} catalog: categories, unique names and descriptions`, () => {
    assert.equal(catalog.length, count);
    const names = catalog.flatMap((g) => g.items.flatMap((i) => i.names));
    assert.equal(new Set(names).size, names.length, 'duplicate name');
    catalog.forEach((g) => {
      assert.ok(g.category && g.items.length > 0);
      g.items.forEach((i) => {
        assert.ok(i.names.length > 0 && i.names.every((n) => /^[A-Za-z0-9]+$/.test(n)), JSON.stringify(i.names));
        assert.ok(i.desc.length > 20, i.names.join('/'));
      });
    });
  });
}
