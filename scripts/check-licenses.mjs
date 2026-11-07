#!/usr/bin/env node
/**
 * License gate — validates the CycloneDX SBOM (produced in CI by syft)
 * against an allowlist of permissive SPDX license ids.
 *
 * Fails on:
 *   - a dependency carrying a non-allowlisted license (copyleft, proprietary…)
 *   - a dependency with no detectable license — it must be added to
 *     EXCEPTIONS explicitly, by name, with a reason. Silent blanks are
 *     how bad licenses slip in.
 *
 * Allowlist rationale: permissive licenses only (MIT/ISC/Apache/BSD and
 * equivalents). Copyleft (GPL/LGPL/AGPL), proprietary or CC-BY-SA are
 * rejected; if one ever shows up it is a deliberate decision, not an
 * accident — allowlist it here with a written justification.
 *
 * Usage: node scripts/check-licenses.mjs sbom.json
 */
import { readFileSync } from 'node:fs';

const ALLOWED = new Set([
  'MIT',
  'ISC',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  '0BSD',
  'Unlicense',
  'CC0-1.0',
  'CC-BY-3.0',
  'CC-BY-4.0',
  'BlueOak-1.0.0',
  'Python-2.0',
  'MPL-2.0',
  'Zlib',
  'MIT-0',
]);

// License-less components we accept deliberately, name → reason.
// Keyed by component name (NOT version — a version bump keeps the
// exception, which is intended for our own private packages).
const EXCEPTIONS = new Map([
  ['cerberus', 'this repo — private, license field intentionally UNLICENSED'],
]);

// SPDX expression keywords that are not license ids.
const EXPRESSION_KEYWORDS = new Set(['OR', 'AND', 'WITH', 'NONE', 'NOASSERTION']);

const path = process.argv[2];
if (path === undefined) {
  console.error('usage: node scripts/check-licenses.mjs <sbom.json>');
  process.exit(2);
}

const sbom = JSON.parse(readFileSync(path, 'utf8'));
if (sbom.bomFormat !== 'CycloneDX') {
  console.error(`not a CycloneDX SBOM: ${path}`);
  process.exit(2);
}

/** All license tokens carried by one component entry. */
function licenseTokens(component) {
  const tokens = [];
  for (const entry of component.licenses ?? []) {
    if (entry.expression !== undefined) {
      // "(MIT OR CC0-1.0)" → check every alternative token.
      for (const token of entry.expression.split(/[\s()]+/)) {
        if (token !== '') tokens.push(token);
      }
    } else {
      const lic = entry.license ?? {};
      tokens.push(lic.id ?? lic.name ?? 'UNKNOWN');
    }
  }
  return tokens;
}

const rejected = [];
const undocumented = [];

for (const component of sbom.components ?? []) {
  const name = component.name ?? 'unknown';

  // Exceptions cover every license state of that component (including an
  // explicit "UNLICENSED" marker).
  if (EXCEPTIONS.has(name)) {
    continue;
  }

  // Some ecosystems mark fuzzy matches with a trailing '*' ("MIT*").
  const tokens = licenseTokens(component).map((t) =>
    t.endsWith('*') ? t.slice(0, -1) : t,
  );

  if (tokens.length === 0) {
    undocumented.push(name);
    continue;
  }

  const bad = tokens.filter(
    (t) => !ALLOWED.has(t) && !EXPRESSION_KEYWORDS.has(t),
  );
  // "NONE"/"NOASSERTION" means syft found no license → same rule as blank.
  if (
    bad.length > 0 ||
    tokens.some((t) => t === 'NONE' || t === 'NOASSERTION')
  ) {
    rejected.push(`${name} — ${tokens.join(' ')}`);
  }
}

if (undocumented.length > 0 || rejected.length > 0) {
  console.error('license gate: FAILED');
  for (const name of [...new Set(undocumented)].sort()) {
    console.error(
      `  no license detected: ${name} — add it to EXCEPTIONS in scripts/check-licenses.mjs with a reason`,
    );
  }
  for (const entry of [...new Set(rejected)].sort()) {
    console.error(`  non-allowlisted license: ${entry}`);
  }
  console.error(`allowed: ${[...ALLOWED].sort().join(', ')}`);
  process.exit(1);
}

console.log(
  `license gate: OK — ${sbom.components?.length ?? 0} components checked`,
);
