## What does this change?

## How was it tested?
- [ ] `npm test` passes (unit tests + KQL parse/type-check)
- [ ] `npm run test:e2e` passes (browser tests)
- [ ] Checked the page manually in light and dark theme

## Checklist
- [ ] New KQL tables/columns were added to `tests/kql-schema.js` from Microsoft's docs
- [ ] Untrusted data is rendered with `textContent`, never `innerHTML`
- [ ] New external hosts were added to the CSP in `index.html` if needed
- [ ] README updated if behaviour or counts changed
