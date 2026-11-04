#!/usr/bin/env node
// Command-line wrapper over the engine build: split, combine, diagnose,
// verify without hand-writing JSON. Print-friendly: shares come out one
// per line so they can be handed out on paper.
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const engine = path.join(root, '_build/js/debug/build/cmd/main/main.js');

function call(request) {
  const result = spawnSync(process.execPath, [engine, '-'],
    {input: JSON.stringify(request), encoding: 'utf8', timeout: 60000});
  const parsed = JSON.parse(result.stdout);
  if (result.status !== 0) {
    console.error('error: ' + parsed.error);
    process.exit(1);
  }
  return parsed;
}

function parseShare(text) {
  // Accepts the one-line form printed by split: index:threshold:digest:data
  if (!text.includes(':')) return JSON.parse(text);
  const [index, threshold, digest, data] = text.split(':');
  return {index: Number(index), threshold: Number(threshold), digest, data};
}

const command = process.argv[2];
const args = process.argv.slice(3);
if (command === 'split' && (args.length === 3 || args.length === 4)) {
  const [hex, threshold, shares, seed] = args;
  const report = call({operation: 'split', secret_hex: hex,
    threshold: Number(threshold), shares: Number(shares),
    seed: seed === undefined ? 0 : Number(seed)});
  console.log(`algorithm ${report.algorithm}  threshold ${report.threshold}` +
    `  shares ${report.shares}  digest ${report.digest}`);
  for (const share of report.share_list) {
    console.log(`${share.index}:${share.threshold}:${share.digest}:${share.data}`);
  }
  console.log('# any ' + report.threshold + ' of the lines above recover the secret');
} else if (command === 'combine' && args.length >= 2) {
  const report = call({operation: 'combine', shares: args.map(parseShare)});
  console.log(`secret_hex ${report.secret_hex}`);
  console.log(`verified ${report.verified}  digest ${report.recovered_digest}`);
} else if (command === 'diagnose' && args.length >= 2) {
  const report = call({operation: 'diagnose', shares: args.map(parseShare)});
  console.log(`consistent ${report.consistent}  subsets ${report.consistent_subsets}/${report.subsets_checked}`);
  console.log(`good ${JSON.stringify(report.good)}`);
  console.log(`suspects ${JSON.stringify(report.suspects)}`);
  if (report.consistent) console.log(`secret_hex ${report.secret_hex}`);
} else if (command === 'verify' && args.length >= 2) {
  const shares = args.filter((a) => a.includes(':') || a.startsWith('['));
  const known = args.filter((a) => !shares.includes(a));
  const request = {operation: 'verify', shares: shares.map(parseShare)};
  if (known.length === 1) request.secret_hex = known[0];
  const report = call(request);
  console.log(`verified ${report.verified}  shares ${report.shares}` +
    `  threshold ${report.threshold}  secret_length ${report.secret_length}`);
} else {
  console.log('Usage:');
  console.log('  shamir.mjs split    <secret-hex> <threshold> <shares> [seed]');
  console.log('  shamir.mjs combine  <share> <share> ...');
  console.log('  shamir.mjs diagnose <share> <share> ...');
  console.log('  shamir.mjs verify   <share> <share> ... [secret-hex]');
  console.log('A share is index:threshold:digest:data or the JSON object form.');
  process.exit(2);
}
