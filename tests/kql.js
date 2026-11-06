/*
 * Thin wrapper around Microsoft's Kusto.Language parser/binder
 * (npm: @kusto/language-service-next) for checking KQL in tests.
 */
'use strict';

global.Bridge = require('@kusto/language-service-next/bridge.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.js');

const K = global.Kusto.Language;
const schemas = require('./kql-schema.js');

let globals = null;
function getGlobals() {
  if (globals) return globals;
  const list = new (global.System.Collections.Generic.List$1(K.Symbols.Symbol)).ctor();
  Object.entries(schemas).forEach(([name, schema]) => list.add(new K.Symbols.TableSymbol.$ctor7(name, schema, null)));
  globals = K.GlobalState.Default.WithDatabase(new K.Symbols.DatabaseSymbol.ctor('security', list));
  return globals;
}

/** Parse + semantically analyse a query. Returns an array of error strings (empty = valid). */
function analyzeKql(query) {
  const code = K.KustoCode.ParseAndAnalyze(query, getGlobals(), null);
  const diagnostics = code.GetDiagnostics();
  const errors = [];
  for (let i = 0; i < diagnostics.Count; i++) {
    const d = diagnostics.getItem(i);
    if (String(d.Severity).toLowerCase() === 'error') {
      const line = query.slice(0, d.Start).split('\n').length;
      errors.push(`line ${line}: ${d.Message}`);
    }
  }
  return errors;
}

module.exports = { analyzeKql };
