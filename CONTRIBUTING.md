# Contributing

Thanks for helping improve CyberGator1. The project is plain HTML/CSS/JS with no build step, so getting started is quick.

## Setup

```bash
git clone https://github.com/indocanadian416/THQV.git
cd THQV
npm install                          # dev tools only: Kusto parser + Playwright
npx playwright install chromium      # once, for the browser tests
python3 -m http.server 8000          # open http://localhost:8000
```

## Tests

| Command | What it checks |
|---|---|
| `npm test` | Unit tests, and parses + type-checks every KQL query against `tests/kql-schema.js` |
| `npm run test:e2e` | Loads the real page in headless Chromium with hostile mocked feeds and drives every tab |
| `npm run check` | Syntax check of every browser script |
| `npm run test:all` | All of the above except `check` |

CI runs all of them on every push and pull request.

## Common contributions

### Add a hunting query
1. Add an entry to `huntingQueries` in `js/queries.js` with `name`, `mitre`, `requires`, `desc` and `query` (use `String.raw` so backslashes stay literal).
2. If the query uses a table or column not in `tests/kql-schema.js`, add it **after checking Microsoft Learn** - the schema is what makes the test meaningful.
3. Run `npm test`. A typo, missing column or broken operator fails with the line number.
4. CrowdStrike queries must use Falcon LogScale syntax (`#event_simpleName=...`, `in()`, `groupBy()`, `table([...])`), not legacy SPL.

### Add or fix an OSINT tool
Edit `osintTools` in `js/osint.js`. To enable direct lookups, add `types` and a `build(value, type)` function, and only use URL formats you have confirmed work. The tests check every claimed type produces a valid https URL.

### Add a hypothesis rule
Add a rule to `RULES` in `js/hypothesis.js` (order matters: first match wins) and a sample article to `tests/osint-hypothesis.test.js`. Generated KQL is type-checked too.

## Rules for UI code

- Never put untrusted data (feed content, user input, storage) into `innerHTML`. Use the `el()` helper in `js/app.js`, which uses `textContent`.
- Pass every external link through `safeHttpUrl()`.
- No inline `<script>`, `onclick=` or `style=` in `index.html`: the CSP blocks them.
- If you add a new network host, add it to the CSP `<meta>` tag.

## Pull requests

Keep them focused, describe how you tested, and update the README if counts or behaviour change.
