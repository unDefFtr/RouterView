/**
 * Convert oui.csv (IEEE OUI registry) to a compact JSON map.
 *
 *   node scripts/build-oui.mjs
 *
 * Input  → oui.csv  (CSV: Registry,Assignment,Org Name,Org Address)
 * Output → backend/src/oui_data.json  ({ "AABBCC": "Org Name", ... })
 *
 * Normalises the Assignment column to uppercase hex without delimiters.
 * Keeps only the first occurrence when duplicates exist.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const fin = readFileSync('oui.csv', 'utf-8');
const lines = fin.split('\n');

const map = Object.create(null);
let header = true;

for (const line of lines) {
  if (!line.trim()) continue;
  if (header) { header = false; continue; }

  // Parse: Registry,Assignment,Org Name,Org Address
  // The Org Name may contain commas inside quotes, so we split manually.
  const parts = parseCsvLine(line);
  if (parts.length < 3) continue;

  const registry = parts[0].trim();
  let assignment = parts[1].trim();
  const orgName = parts[2].trim().replace(/^"(.*)"$/, '$1');

  // Only MA-L entries have a 6-char OUI (24-bit)
  if (registry !== 'MA-L') continue;

  // Normalise: uppercase, strip separators, pad to 6 hex chars
  assignment = assignment.replace(/[-:]/g, '').toUpperCase();
  if (assignment.length < 6) continue;
  assignment = assignment.substring(0, 6);
  if (!/^[0-9A-F]{6}$/.test(assignment)) continue;

  // Keep first occurrence (duplicates exist for same OUI under different orgs)
  if (!(assignment in map)) {
    map[assignment] = orgName;
  }
}

// Sort keys for deterministic output and smaller gzip
const sorted = Object.create(null);
for (const k of Object.keys(map).sort()) {
  sorted[k] = map[k];
}

const outPath = 'backend/src/oui_data.json';
writeFileSync(outPath, JSON.stringify(sorted));
console.log(`Wrote ${Object.keys(sorted).length} OUI entries → ${outPath}`);
console.log(`Size: ${(JSON.stringify(sorted).length / 1024).toFixed(0)} KB`);

/** Split a CSV line that may have quoted fields with commas inside. */
function parseCsvLine(line) {
  const result = [];
  let current = '';
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuote = !inQuote;
      current += '"';
    } else if (ch === ',' && !inQuote) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}
