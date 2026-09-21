## What does this PR do?

<!-- One-paragraph summary of the change. -->

## Why is this change needed?

<!-- Link the issue this fixes, or describe the gap. -->

## How was it tested?

<!--
- [ ] `npm run build` exits 0
- [ ] `npm run lint` passes
- [ ] `node dist/main.js` boots both listeners without errors
- [ ] Manual smoke-test of changed endpoints (describe below)
- [ ] Migration applied cleanly to a fresh DB

If any box is unchecked, explain why in "Notes".
-->

### Manual test steps

1.
2.
3.

## Checklist

- [ ] No new `V1.5 will add` / `TODO` comments in code paths I touched
- [ ] OpenAPI spec updated if I added/changed any REST endpoint
- [ ] GraphQL SDL updated if I added/changed any GraphQL operation
- [ ] Postman collection regenerated (`npm run postman:generate`) if endpoints changed
- [ ] Audit log row written for any state-changing operation I added
- [ ] `git commit` messages describe WHY, not WHAT

## Notes for reviewer

<!-- Anything unusual. Migration notes, breaking changes, design trade-offs. -->
