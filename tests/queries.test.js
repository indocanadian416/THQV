'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { huntingQueries, PLATFORMS, queryStats } = require('../js/queries.js');
const { analyzeKql } = require('./kql.js');

const all = [];
for (const [platform, cats] of Object.entries(huntingQueries)) {
  for (const [category, list] of Object.entries(cats)) list.forEach((q) => all.push({ platform, category, q }));
}

test('every query has the required metadata', () => {
  for (const { platform, q } of all) {
    assert.ok(PLATFORMS[platform], 'unknown platform ' + platform);
    assert.ok(q.name && q.desc && q.requires && q.query, 'missing field in ' + q.name);
    assert.ok(q.mitre.length > 0, q.name + ' has no ATT&CK technique');
    q.mitre.forEach((t) => assert.match(t, /^T\d{4}(\.\d{3})?$/, q.name + ': bad technique id ' + t));
  }
});

test('query names are unique per platform', () => {
  for (const platform of Object.keys(huntingQueries)) {
    const names = all.filter((x) => x.platform === platform).map((x) => x.q.name);
    assert.equal(new Set(names).size, names.length, 'duplicate query name in ' + platform);
  }
});

for (const { platform, q } of all.filter((x) => PLATFORMS[x.platform].language === 'kql')) {
  test(`KQL parses and type-checks: [${platform}] ${q.name}`, () => {
    assert.deepEqual(analyzeKql(q.query), []);
  });
}

for (const { q } of all.filter((x) => PLATFORMS[x.platform].language === 'logscale')) {
  test(`LogScale lint: ${q.name}`, () => {
    const body = q.query.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
    assert.match(body, /^#event_simpleName=/m, 'should start from a #event_simpleName filter');
    // Legacy Splunk-style (SPL) constructs that LogScale does not accept:
    assert.doesNotMatch(body, /\|\s*(stats|where|search|eval|rename)\b/i, 'SPL command used');
    assert.doesNotMatch(body, /\bIN\s*\(/, 'SPL IN (...) used - use in(field=..., values=[...])');
    assert.doesNotMatch(body, /\|\s*table\s+[^(\s]/, 'SPL table syntax - use table([...])');
    assert.doesNotMatch(body, /(^|[^#])\bevent_simpleName=/m, 'use the #event_simpleName tag field');
  });
}

test('queryStats counts what is really in the library', () => {
  const s = queryStats();
  assert.equal(s.queries, all.length);
  assert.equal(s.platforms, Object.keys(huntingQueries).length);
  assert.equal(s.categories, new Set(all.map((x) => x.category)).size);
});

test('the checker itself rejects broken KQL', () => {
  assert.notDeepEqual(analyzeKql('DeviceNetworkEvents | where BytesSent > 1'), []);
  assert.notDeepEqual(analyzeKql('SigninLogs | summarize count() by UserPrincipalName | project TimeGenerated'), []);
  assert.notDeepEqual(analyzeKql('SigninLogs | where'), []);
});
