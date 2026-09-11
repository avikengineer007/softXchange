#!/usr/bin/env node
/**
 * softXchange — 3D Asset Budget Enforcer
 * Fails with exit code 1 if any .glb exceeds the per-model or total budget.
 *
 * Usage:
 *   node check-asset-budget.js
 *   ASSET_BUDGET_KB=120 TOTAL_BUDGET_KB=3000 node check-asset-budget.js
 *
 * Budget defaults:
 *   Per model: 80 KB
 *   Total hero scene: 2000 KB (2 MB)
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const ASSET_DIR       = path.resolve(__dirname);
const PER_MODEL_KB    = parseInt(process.env.ASSET_BUDGET_KB   || '80',   10);
const TOTAL_KB        = parseInt(process.env.TOTAL_BUDGET_KB   || '2000', 10);

const files = fs.readdirSync(ASSET_DIR).filter(f => f.endsWith('.glb'));

if (files.length === 0) {
  console.error('✗  No .glb files found in', ASSET_DIR);
  console.error('   Run: npm run 3d:generate');
  process.exit(1);
}

const BAR = '─'.repeat(52);
console.log(`\n softXchange Asset Budget Check`);
console.log(` Per-model limit : ${PER_MODEL_KB} KB`);
console.log(` Total limit     : ${TOTAL_KB} KB`);
console.log(`\n ${'File'.padEnd(20)} ${'Size (KB)'.padStart(10)}   Status`);
console.log(` ${BAR}`);

let totalBytes = 0;
let failures   = [];

for (const file of files.sort()) {
  const filePath = path.join(ASSET_DIR, file);
  const bytes    = fs.statSync(filePath).size;
  const kb       = (bytes / 1024).toFixed(1);
  totalBytes    += bytes;

  const over   = bytes > PER_MODEL_KB * 1024;
  const status = over ? `✗ OVER ${PER_MODEL_KB} KB limit` : '✓';
  console.log(` ${file.padEnd(20)} ${kb.padStart(10)} KB   ${status}`);

  if (over) failures.push(file);
}

const totalKB = (totalBytes / 1024).toFixed(1);
const totalOver = totalBytes > TOTAL_KB * 1024;
console.log(` ${BAR}`);
console.log(` ${'TOTAL'.padEnd(20)} ${totalKB.padStart(10)} KB   ${totalOver ? `✗ OVER ${TOTAL_KB} KB limit` : '✓'}`);
console.log('');

if (failures.length > 0) {
  console.error(`✗  ${failures.length} asset(s) exceed the ${PER_MODEL_KB} KB per-model limit:`);
  failures.forEach(f => console.error(`     ${f}`));
}
if (totalOver) {
  console.error(`✗  Total 3D asset payload (${totalKB} KB) exceeds ${TOTAL_KB} KB limit`);
}

if (failures.length > 0 || totalOver) {
  console.error('');
  console.error('   Reduce geometry complexity or compress with gltf-pipeline / Draco.');
  process.exit(1);
} else {
  console.log(' ✓ All assets within budget.\n');
  process.exit(0);
}
