'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { defenderTables, crowdstrikeEvents, crowdstrikeJoinNotes } = require('../js/tables.js');
const schemas = require('./kql-schema.js');
const { analyzeKql } = require('./kql.js');

/** Parse "(Name:type, Other:type)" into a Map name -> type. */
function parseSchema(schema) {
  const map = new Map();
  schema.replace(/^\(|\)$/g, '').split(',').forEach((pair) => {
    const [name, type] = pair.trim().split(':');
    map.set(name, type);
  });
  return map;
}

test('reference covers a useful set of tables and events', () => {
  assert.ok(defenderTables.length >= 15, 'Defender tables: ' + defenderTables.length);
  assert.ok(crowdstrikeEvents.length >= 10, 'CrowdStrike events: ' + crowdstrikeEvents.length);
  assert.ok(crowdstrikeJoinNotes.length > 0);
  assert.equal(new Set(defenderTables.map((t) => t.name)).size, defenderTables.length, 'duplicate Defender table');
  assert.equal(new Set(crowdstrikeEvents.map((t) => t.name)).size, crowdstrikeEvents.length, 'duplicate CrowdStrike event');
});

for (const table of defenderTables) {
  test(`Defender ${table.name}: columns match the documented schema`, () => {
    assert.ok(schemas[table.name], `${table.name} is missing from tests/kql-schema.js`);
    const schema = parseSchema(schemas[table.name]);
    assert.ok(table.columns.length >= 5, 'list at least 5 key columns');
    for (const col of table.columns) {
      assert.ok(schema.has(col.name), `${table.name}.${col.name} is not a documented column`);
      assert.equal(col.type, schema.get(col.name), `${table.name}.${col.name} type`);
      assert.ok(col.desc && col.desc.length > 5, `${table.name}.${col.name} needs a description`);
    }
  });

  test(`Defender ${table.name}: sample uses listed columns and starter query type-checks`, () => {
    const names = new Set(table.columns.map((c) => c.name));
    Object.keys(table.sample).forEach((k) => assert.ok(names.has(k), `${table.name} sample field ${k} is not in its column list`));
    assert.ok(table.summary && table.huntFor.length >= 2 && /^https:\/\/learn\.microsoft\.com\//.test(table.docs));
    assert.deepEqual(analyzeKql(table.starter), []);
  });
}

for (const ev of crowdstrikeEvents) {
  test(`CrowdStrike ${ev.name}: fields, sample and starter query`, () => {
    assert.ok(ev.fields.length >= 4, 'list at least 4 fields');
    assert.ok(ev.fields.some((f) => f.name === 'aid'), 'aid should be listed');
    const names = new Set(ev.fields.map((f) => f.name));
    Object.keys(ev.sample).filter((k) => k !== '#event_simpleName').forEach((k) => assert.ok(names.has(k), `${ev.name} sample field ${k} not listed`));
    assert.ok(ev.summary && ev.huntFor.length >= 2);
    const body = ev.starter.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
    assert.match(body, /^#event_simpleName=/m);
    assert.doesNotMatch(body, /\|\s*(stats|where|search|eval|rename)\b/i, 'SPL command used');
    assert.doesNotMatch(body, /\bIN\s*\(/, 'SPL IN (...) used');
    const pattern = ev.eventPattern || ev.name;
    assert.ok(body.includes('#event_simpleName=' + pattern), `starter should query ${pattern}`);
  });
}
