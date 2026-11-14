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
  // Accepts the one-line form printed by split:
  //   index:threshold:digest:encoding:data   (current)
  //   index:threshold:digest:data            (legacy hex)
  if (!text.includes(':')) return JSON.parse(text);
  const parts = text.split(':');
  if (parts.length === 4) {
    const [index, threshold, digest, data] = parts;
    return {index: Number(index), threshold: Number(threshold), digest, data};
  }
  const [index, threshold, digest, encoding, ...rest] = parts;
  return {index: Number(index), threshold: Number(threshold), digest,
    encoding, data: rest.join(':')};
}

// Words shares contain spaces, so an unquoted line arrives as several
// argv entries. Reassemble: an argument that starts a one-line share
// (index:threshold:8-hex-digits:) opens a share; anything else is a
// continuation of the previous share's payload.
function gatherShares(args) {
  const opener = /^\d+:\d+:[0-9a-f]{8}:[a-z0-9]+:/;
  const lines = [];
  for (const arg of args) {
    if (opener.test(arg) || lines.length === 0) {
      lines.push(arg);
    } else {
      lines[lines.length - 1] += ' ' + arg;
    }
  }
  return lines.map(parseShare);
}

const command = process.argv[2];
const args = process.argv.slice(3);
function usage() {
  console.log('Usage:');
  console.log('  shamir.mjs split    <secret-hex> <threshold> <shares> [seed]');
  console.log('  shamir.mjs split-many <threshold> <shares> <seed> <hex> <hex> ...');
  console.log('  shamir.mjs combine  <share> <share> ...');
  console.log('  shamir.mjs diagnose <share> <share> ...');
  console.log('  shamir.mjs verify   <share> <share> ... [secret-hex]');
  console.log('  shamir.mjs reshare  <threshold-new> <shares-new> <seed> <share>...');
  console.log('  shamir.mjs kdf      <password> [salt-hex] [iterations]');
  console.log('  shamir.mjs info     <share>');
  console.log('  shamir.mjs fingerprint <share> <share> ...');
  console.log('  shamir.mjs sort     [encoding] <share> <share> ...');
  console.log('  shamir.mjs check    <share> <share> ...');
  console.log('  shamir.mjs quorum-check <share> <share> ...');
  console.log('A share is index:threshold:digest:data or the JSON object form.');
  process.exit(2);
}
if (command === 'split' && (args.length >= 3 && args.length <= 5)) {
  const [hex, threshold, shares, seed, encoding] = args;
  const request = {operation: 'split', secret_hex: hex,
    threshold: Number(threshold), shares: Number(shares),
    seed: seed === undefined ? 0 : Number(seed)};
  if (encoding !== undefined) request.share_encoding = encoding;
  const report = call(request);
  console.log(`algorithm ${report.algorithm}  threshold ${report.threshold}` +
    `  shares ${report.shares}  digest ${report.digest}`);
  for (const share of report.share_list) {
    console.log(`${share.index}:${share.threshold}:${share.digest}:${share.encoding}:${share.data}`);
  }
  console.log('# any ' + report.threshold + ' of the lines above recover the secret');
} else if (command === 'combine' && args.length >= 2) {
  const report = call({operation: 'combine', shares: gatherShares(args)});
  console.log(`secret_hex ${report.secret_hex}`);
  console.log(`verified ${report.verified}  digest ${report.recovered_digest}`);
} else if (command === 'diagnose' && args.length >= 2) {
  const report = call({operation: 'diagnose', shares: gatherShares(args)});
  console.log(`consistent ${report.consistent}  subsets ${report.consistent_subsets}/${report.subsets_checked}`);
  console.log(`good ${JSON.stringify(report.good)}`);
  console.log(`suspects ${JSON.stringify(report.suspects)}`);
  if (report.consistent) console.log(`secret_hex ${report.secret_hex}`);
} else if (command === 'verify' && args.length >= 2) {
  const shares = args.filter((a) => a.includes(':') || a.startsWith('['));
  const known = args.filter((a) => !shares.includes(a));
  const request = {operation: 'verify', shares: gatherShares(shares)};
  if (known.length === 1) request.secret_hex = known[0];
  const report = call(request);
  console.log(`verified ${report.verified}  shares ${report.shares}` +
    `  threshold ${report.threshold}  secret_length ${report.secret_length}`);
} else if (command === 'reshare' && args.length >= 4) {
  // reshare <threshold_new> <shares_new> <seed> <share>...
  const [thresholdNew, sharesNew, seed, ...shareArgs] = args;
  const report = call({operation: 'reshare',
    shares: gatherShares(shareArgs),
    threshold_new: Number(thresholdNew), shares_new: Number(sharesNew),
    seed: Number(seed)});
  console.log(`threshold ${report.threshold_new}  shares ${report.shares_new}` +
    `  digest ${report.digest}  commit ${report.commit}`);
  for (const share of report.share_list) {
    console.log(`${share.index}:${share.threshold}:${share.digest}:${share.encoding}:${share.data}`);
  }
  console.log('# any ' + report.threshold_new + ' of the lines above recover the same secret');
} else if (command === 'split-many' && args.length >= 4) {
  // split-many <threshold> <shares> <seed> <hex> <hex> ...
  const [threshold, shares, seed, ...secrets] = args;
  const report = call({operation: 'split_many', secrets,
    threshold: Number(threshold), shares: Number(shares),
    seed: Number(seed)});
  console.log(`secrets ${report.secrets}  threshold ${report.threshold}` +
    `  shares ${report.shares}  encoding ${report.share_encoding}`);
  for (const split of report.splits) {
    console.log(`# secret ${split.position}: ${split.secret_bytes}B digest ${split.digest}`);
    for (const share of split.share_list) {
      console.log(`${share.index}:${share.threshold}:${share.digest}:${share.encoding}:${share.data}`);
    }
  }
} else if (command === 'fingerprint' && args.length >= 1) {
  const report = call({operation: 'fingerprint', shares: gatherShares(args)});
  console.log(`fingerprint ${report.fingerprint}  shares ${report.shares}` +
    `  threshold ${report.threshold}`);
  const ids = report.share_ids.map((s) => s.index + ':' + s.id).join(' ');
  console.log(`ids ${ids}`);
} else if (command === 'sort' && args.length >= 1) {
  // sort [encoding] <share> <share> ... - canonical order, uniform payload
  // encoding (hex by default), no recovery attempted.
  let encoding;
  if (!/^\d/.test(args[0]) && args[0] !== '[') {
    encoding = args[0];
    args = args.slice(1);
  }
  if (args.length < 1) { usage(); }
  const request = {operation: 'sort', shares: gatherShares(args)};
  if (encoding !== undefined) request.share_encoding = encoding;
  const report = call(request);
  console.log(`algorithm ${report.algorithm}  shares ${report.shares}` +
    `  threshold ${report.threshold}  digest ${report.digest}`);
  for (const share of report.share_list) {
    console.log(`${share.index}:${share.threshold}:${share.digest}:${share.encoding}:${share.data}`);
  }
} else if (command === 'check' && args.length >= 1) {
  const report = call({operation: 'check', shares: gatherShares(args)});
  console.log(`ready ${report.ready}  gap ${report.gap}  shares ${report.shares}` +
    `  threshold ${report.threshold}`);
  console.log(`digest ${report.digest}  commit ${report.commit}` +
    `  payload ${report.payload_bytes}B` +
    (report.authenticated ? '  authenticated' : ''));
} else if (command === 'quorum-check' && args.length >= 1) {
  const report = call({operation: 'quorum_check', shares: gatherShares(args)});
  console.log(`ready ${report.ready}  gap ${report.gap}  excess ${report.excess}` +
    `  shares ${report.shares}  threshold ${report.threshold}` +
    `  quorums ${report.quorums === null ? '>2^53' : report.quorums}` +
    `  crosscheck_ready ${report.crosscheck_ready}`);
  console.log(`digest ${report.digest}  commit ${report.commit}` +
    `  payload ${report.payload_bytes}B` +
    (report.authenticated ? '  authenticated' : ''));
} else if (command === 'info' && args.length >= 1) {
  const share = gatherShares(args)[0];
  const report = call({operation: 'info', share});
  console.log(`index ${report.index}  threshold ${report.threshold}` +
    `  payload ${report.payload_bytes}B`);
  console.log(`digest ${report.digest}  commit ${report.commit}` +
    `  authenticated ${report.authenticated}` +
    (report.mac ? `  mac ${report.mac}` : ''));
  console.log(`checksum_ok ${report.checksum_ok}`);
} else if (command === 'kdf' && args.length >= 1 && args.length <= 3) {
  const [password, salt, iterations] = args;
  const request = {operation: 'kdf', password};
  if (salt !== undefined) request.salt_hex = salt;
  if (iterations !== undefined) request.iterations = Number(iterations);
  const report = call(request);
  console.log(`algorithm ${report.algorithm}  iterations ${report.iterations}` +
    `  salt ${report.salt_hex}`);
  console.log(`seed ${report.seed}`);
} else {
  usage();
}
