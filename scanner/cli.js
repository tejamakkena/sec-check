#!/usr/bin/env node
// sec-check CLI: scan a project folder on your machine. Nothing is uploaded.
//
//   node scanner/cli.js [path] [--json] [--fail-on=critical|high|medium|low|none]

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { scanProject, isScannable, SKIP_DIRS, SEVERITIES, MAX_FILE_BYTES } from './rules.js';
import { readGitIndex } from './git-index.js';

const HELP = `sec-check: security check for AI-built apps

Usage: sec-check [path] [options]

Options:
  --json               Print findings as JSON
  --fail-on=<level>    Exit 1 if any finding is at or above this severity
                       (critical, high, medium, low, none). Default: high
  --no-prompts         Hide the copy-paste AI fix prompts
  -h, --help           Show this help

Add "sec-check-ignore" to a line to silence a finding on it.`;

function parseArgs(argv) {
  const opts = { root: '.', json: false, failOn: 'high', prompts: true };
  for (const arg of argv) {
    if (arg === '-h' || arg === '--help') { console.log(HELP); process.exit(0); }
    else if (arg === '--json') opts.json = true;
    else if (arg === '--no-prompts') opts.prompts = false;
    else if (arg.startsWith('--fail-on=')) opts.failOn = arg.slice('--fail-on='.length);
    else if (arg.startsWith('-')) { console.error(`Unknown option: ${arg}\n\n${HELP}`); process.exit(2); }
    else opts.root = arg;
  }
  if (opts.failOn !== 'none' && !SEVERITIES.includes(opts.failOn)) {
    console.error(`--fail-on must be one of: ${SEVERITIES.join(', ')}, none`);
    process.exit(2);
  }
  return opts;
}

function collectFiles(root) {
  const files = [];
  const walk = dir => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
      } else if (entry.isFile()) {
        const path = relative(root, full).split(sep).join('/');
        if (!isScannable(path) || statSync(full).size > MAX_FILE_BYTES) continue;
        files.push({ path, content: readFileSync(full, 'utf8') });
      }
    }
  };
  walk(root);
  return files;
}

// Paths committed to git, relative to root, or null if unknown. Reads
// .git/index directly instead of running git (see git-index.js for why).
function trackedFiles(root) {
  let repo = root;
  while (!existsSync(join(repo, '.git'))) {
    if (dirname(repo) === repo) return null;
    repo = dirname(repo);
  }
  try {
    const paths = readGitIndex(readFileSync(join(repo, '.git', 'index')));
    const prefix = relative(repo, root).split(sep).join('/');
    if (!prefix) return paths;
    return new Set([...paths].filter(p => p.startsWith(`${prefix}/`)).map(p => p.slice(prefix.length + 1)));
  } catch {
    return null; // worktree or submodule (.git is a file), no commits yet, or an unknown format
  }
}

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = code => text => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const bold = paint('1'), dim = paint('2');
const SEVERITY_STYLE = { critical: paint('1;41;97'), high: paint('1;31'), medium: paint('1;33'), low: paint('1;36') };

function wrap(text, indent, width = Math.min(process.stdout.columns || 100, 100)) {
  const lines = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (line && indent.length + line.length + word.length + 1 > width) { lines.push(line); line = word; }
    else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(line);
  return lines.map(l => indent + l).join('\n');
}

function printReport(result, opts) {
  const { findings, summary, grade, filesScanned } = result;
  console.log(`\n${bold('sec-check')} ${dim(`scanned ${filesScanned} files in ${opts.root}`)}\n`);
  for (const f of findings) {
    const where = `${f.file}:${f.line}${f.occurrences > 1 ? ` (+${f.occurrences - 1} more)` : ''}`;
    console.log(`${SEVERITY_STYLE[f.severity](` ${f.severity.toUpperCase()} `)} ${bold(f.title)}`);
    console.log(`  ${dim(where)}   ${dim(f.evidence)}`);
    console.log(wrap(f.why, '  '));
    console.log(wrap(`Fix: ${f.fix}`, '  '));
    if (opts.prompts) console.log(`${dim('  Paste into your AI tool:')}\n${dim(wrap(f.prompt, '  │ '))}`);
    console.log('');
  }
  const counts = SEVERITIES.map(s => `${summary[s]} ${s}`).join(', ');
  if (findings.length === 0) console.log(`${bold('Grade A')}: no issues found. ${dim('sec-check reads code only, so also review your live database and hosting settings.')}`);
  else console.log(`${bold(`Grade ${grade}`)}: ${counts}`);
  console.log('');
}

const opts = parseArgs(process.argv.slice(2));
const root = resolve(opts.root);
try {
  if (!statSync(root).isDirectory()) throw new Error('not a directory');
} catch {
  console.error(`sec-check: ${opts.root} is not a directory`);
  process.exit(2);
}

const result = scanProject(collectFiles(root), { tracked: trackedFiles(root) });
if (opts.json) console.log(JSON.stringify(result, null, 2));
else printReport(result, opts);

const threshold = SEVERITIES.indexOf(opts.failOn);
const failed = opts.failOn !== 'none' && result.findings.some(f => SEVERITIES.indexOf(f.severity) <= threshold);
process.exit(failed ? 1 : 0);
