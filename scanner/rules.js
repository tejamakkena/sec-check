// sec-check rules engine.
//
// Pure functions only (no Node or DOM APIs) so the same module runs in the
// CLI (scanner/cli.js) and in the browser (scan.html). Input is a list of
// { path, content } with POSIX-style paths relative to the project root.

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '.nuxt', '.output', '.svelte-kit',
  '.vercel', '.netlify', '.turbo', '.cache', '.parcel-cache', 'coverage', 'out', 'vendor',
  '.expo', '__pycache__', '.venv', 'venv', '.idea', '.vscode',
]);

const SCAN_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?|sql|rules|json|toml|ya?ml|py|rb|go|php|sh)$/i;
const LOCKFILE = /^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|composer\.lock|poetry\.lock|Cargo\.lock)$/;
const ENV_FILE = /^\.env(?:\.[\w.-]+)?$/;
const ENV_EXAMPLE = /\.(?:example|sample|template|dist|defaults?)$/i;
const CODE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?)$/i;
const SERVER_PATH = /(?:^|\/)(?:api|server|backend|functions|lambdas?|edge-functions|scripts|migrations)(?:\/|$)|\.server\.[cm]?[jt]sx?$|(?:^|\/)(?:route|middleware)\.[jt]s$|(?:^|\/)\+(?:server|page\.server|layout\.server)\.[jt]s$/i;
const CONFIG_FILE = /(?:^|\/)[^/]*\.config\.[cm]?[jt]s$/i;
const SERVER_FRAMEWORKS = [
  'next', 'nuxt', '@sveltejs/kit', 'astro', '@remix-run/node', '@remix-run/react', '@tanstack/start',
  '@tanstack/react-start', 'express', 'fastify', 'hono', 'koa', '@nestjs/core',
];

export const MAX_FILE_BYTES = 1024 * 1024;

/** Whether a project-relative path is worth reading at all. */
export function isScannable(path) {
  const parts = path.split('/');
  if (parts.slice(0, -1).some(p => SKIP_DIRS.has(p))) return false;
  const name = parts[parts.length - 1];
  if (LOCKFILE.test(name) || /\.min\.js$/i.test(name)) return false;
  if (name === '.gitignore' || ENV_FILE.test(name)) return true;
  return SCAN_EXT.test(name);
}

// ── Rule copy ────────────────────────────────────────────────────────────
// Written for people who built their app with an AI tool and may not read
// code: what is wrong, why it matters, how to fix it, and a prompt they can
// paste back into Lovable / Bolt / Cursor / Replit.

const ROTATE = 'Assume it is already leaked: revoke it and create a new one in the provider dashboard.';

export const RULES = {
  'secret-in-code': {
    name: 'Secret keys in source code',
    summary: 'Stripe, OpenAI, Anthropic, AWS, GitHub, Slack and private keys pasted into code.',
    title: v => `${v.label} hardcoded in ${v.client ? 'browser code' : 'source code'}`,
    why: v => v.client
      ? 'This file is bundled into your website, so any visitor can open DevTools and copy the key. Bots look for exactly this and can run up charges or reach your data within minutes.'
      : 'Anyone who can see this repository can copy the key, and it stays in git history even after you delete the line.',
    fix: v => `${ROTATE} Then store the new key in a server-only environment variable (for example ${v.envName}, with no NEXT_PUBLIC_/VITE_ prefix) and use it only from server code: an API route, server action or Supabase Edge Function.`,
    prompt: v => `My app has a ${v.label} hardcoded in ${v.file} (line ${v.line}). Remove it from the code and read it from a server-only environment variable named ${v.envName} instead. Make sure it is only used in server-side code (an API route, server action or Supabase Edge Function) and never in code that runs in the browser. If the frontend currently calls the provider directly with this key, add a small server endpoint that makes the call and have the frontend call that endpoint. Do not log or print the key, and make sure .env files are listed in .gitignore.`,
  },
  'supabase-service-key': {
    name: 'Supabase service_role / secret key exposed',
    summary: 'The key that bypasses all row-level security, found outside server-only env files.',
    title: v => `Supabase ${v.kind} key in ${v.client ? 'browser code' : 'source code'}`,
    why: () => 'This key bypasses every row-level security policy. Whoever has it can read, change or delete every row in your database and every user account.',
    fix: () => `${ROTATE} (Supabase → Project Settings → API Keys.) Use the anon / publishable key in the frontend and keep the service key only in server-side code such as Edge Functions.`,
    prompt: v => `My Supabase service_role (secret) key is in ${v.file} (line ${v.line}). Remove it from that file. The frontend Supabase client must use only the anon/publishable key. Anything that genuinely needs admin access should move into a Supabase Edge Function (or other server code) that reads the key from the SUPABASE_SERVICE_ROLE_KEY environment variable and checks that the calling user is allowed to do the action. List every place that used the service key and what you changed.`,
  },
  'public-env-secret': {
    name: 'Secrets in browser-exposed env vars',
    summary: 'NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ … variables that hold secrets.',
    title: v => `${v.name} is exposed to the browser`,
    why: v => `Variables starting with ${v.prefix} are copied into the JavaScript that every visitor downloads. The ${v.prefix} prefix makes this value public, wherever it is set.`,
    fix: v => `Rename it without the ${v.prefix} prefix, rotate the value, and read it only in server-side code. If the page needs the result, add a server endpoint that uses the secret and returns just what the page needs.`,
    prompt: v => `The environment variable ${v.name} holds a secret but its ${v.prefix} prefix ships it to the browser (seen in ${v.file}, line ${v.line}). Rename it to ${v.name.slice(v.prefix.length)} (no public prefix), update every place that reads it, and move that code to the server: an API route, server action or Supabase Edge Function that the frontend calls. The browser must never receive the secret value.`,
  },
  'env-not-ignored': {
    name: '.env files that can end up in git',
    summary: '.env files that are committed, or not covered by .gitignore.',
    title: v => v.committed ? `${v.file} is committed to git` : `${v.file} is not covered by .gitignore`,
    why: v => v.committed
      ? 'This file holds your real keys and is part of the repository, so everyone who can see the repo has them. Deleting it now does not remove it from git history.'
      : 'Environment files hold your real keys. Without a .gitignore entry, the next "git add ." will commit them.',
    fix: v => v.committed
      ? 'Rotate every key in the file, run "git rm --cached" on it, and add ".env*" (plus "!.env.example") to .gitignore.'
      : 'Add ".env*" (plus "!.env.example" if you keep one) to .gitignore.',
    prompt: v => `Make sure ${v.file} is never committed: add ".env*" and "!.env.example" to .gitignore${v.committed ? `, and stop tracking it with git rm --cached ${v.file}` : ''}. Create a .env.example that lists the same variable names with empty values so others know what to set.`,
  },
  'supabase-rls-missing': {
    name: 'Supabase tables without row-level security',
    summary: 'Tables in the public schema that never enable RLS, or explicitly disable it.',
    title: v => v.disabled ? `Row-level security is disabled on "${v.table}"` : `Row-level security is off for table "${v.table}"`,
    why: v => `Supabase serves every table in the public schema through its API, and the anon key that makes this work is public (it is in your frontend). Without RLS, anyone can read, edit or delete every row in "${v.table}" with a single request.`,
    fix: v => `Add a migration with "ALTER TABLE public.${v.table} ENABLE ROW LEVEL SECURITY;" and then add policies for exactly who may read and write, for example "auth.uid() = user_id".`,
    prompt: v => `In Supabase, the table public.${v.table} (${v.disabled ? 'RLS disabled' : 'created'} in ${v.file}) does not have row level security enabled. Create a new migration that runs ALTER TABLE public.${v.table} ENABLE ROW LEVEL SECURITY; and adds policies so users can only select, insert, update and delete their own rows, by comparing auth.uid() to the table's owner column. If there is no owner column, tell me and suggest one. If some of this data is meant to be public, add a separate read-only SELECT policy for just that. Do not use USING (true) for insert, update or delete.`,
  },
  'supabase-open-policy': {
    name: 'Supabase policies that let anyone in',
    summary: 'Policies using USING (true), WITH CHECK (true) or "any logged-in user" checks.',
    title: v => `Policy "${v.policy}" lets ${v.who} ${v.verb} ${v.write ? 'any' : 'every'} row in "${v.table}"`,
    why: v => v.write
      ? `This policy checks ${v.trivial === 'true' ? 'nothing' : 'only that someone is logged in'}, not who owns the row, so ${v.who} can change other people's data in "${v.table}".`
      : `Every row in "${v.table}" is readable by ${v.who}. That is fine for public content like blog posts or products, but a leak if the table holds personal data, emails or private messages.`,
    fix: v => v.write
      ? `Replace the condition with an ownership check, e.g. USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id).`
      : 'If the table is not meant to be public, restrict the SELECT policy to the row owner, e.g. USING (auth.uid() = user_id).',
    prompt: v => `In ${v.file} (line ${v.line}), the Supabase policy "${v.policy}" on table "${v.table}" lets ${v.who} ${v.verb} ${v.write ? 'any' : 'every'} row. Write a new migration that drops this policy and replaces it with one that only allows users to ${v.verb} their own rows (compare auth.uid() to the owner column), keeping any access that is genuinely meant to be public. Explain what changed.`,
  },
  'firebase-open-rules': {
    name: 'Open Firebase security rules',
    summary: 'Firestore, Storage and Realtime Database rules that allow everyone, or are in "test mode".',
    title: v => v.testMode ? `Firebase ${v.kind} rules are still in test mode` : `Firebase ${v.kind} rules allow ${v.ops} for everyone`,
    why: v => v.testMode
      ? 'Test-mode rules let anyone read and write everything until a date, after which the app breaks. Either way, your data is open now.'
      : v.write
        ? 'Anyone on the internet can create, overwrite or delete data, no account needed.'
        : 'Anyone on the internet can read this data, no account needed. Fine only for truly public content.',
    fix: () => 'Require sign-in and ownership, e.g. "allow read, write: if request.auth != null && request.auth.uid == userId;" on a per-user path, and test with the Firebase Rules Playground.',
    prompt: v => `My Firebase ${v.kind} rules in ${v.file} (line ${v.line}) ${v.testMode ? 'are in test mode' : `allow ${v.ops} for everyone`}. Rewrite the rules so each signed-in user can only read and write their own data (match on request.auth.uid), keep anything that is truly public as read-only, and deny everything else by default. Explain each rule you write.`,
  },
  'llm-key-in-browser': {
    name: 'AI APIs called from the browser',
    summary: 'OpenAI / Anthropic / Gemini / Groq calls made from frontend code.',
    title: v => `${v.provider} API called directly from the browser`,
    why: v => `To call ${v.provider} from the browser the API key has to be in the page, so anyone can copy it and spend your credits.`,
    fix: () => 'Move the call into a server endpoint or Supabase Edge Function that holds the key, and have the frontend call that endpoint. Add a per-user rate limit there.',
    prompt: v => `${v.file} (line ${v.line}) calls the ${v.provider} API directly from the browser, which exposes my API key. Move this call into a server endpoint (an API route or Supabase Edge Function) that reads the key from a server-only environment variable, require the user to be signed in, add a simple per-user rate limit, and have the frontend call that endpoint instead. Remove the key and any dangerouslyAllowBrowser option from frontend code.`,
  },
  'supabase-admin-in-client': {
    name: 'Supabase admin API in browser code',
    summary: 'auth.admin calls in frontend code, which require the service_role key.',
    title: () => 'Supabase admin API used in browser code',
    why: () => 'auth.admin only works with the service_role key, so this code either ships that key to every visitor or does not work.',
    fix: () => 'Move admin actions into a Supabase Edge Function that checks the caller is an admin, and call it from the frontend.',
    prompt: v => `${v.file} (line ${v.line}) uses supabase.auth.admin in frontend code. Move each admin operation into a Supabase Edge Function that uses the service role key from its environment, verifies the calling user is actually an admin, and returns only what the UI needs. Update the frontend to call the function.`,
  },
  'supabase-unverified': {
    name: 'Supabase RLS you should check by hand',
    summary: 'Supabase projects without SQL migrations, where RLS cannot be verified from code.',
    title: () => 'Could not verify Supabase row-level security',
    why: () => 'This project uses Supabase but has no SQL migrations, so the tables were probably created in the dashboard and sec-check cannot see whether RLS is on.',
    fix: () => 'Open your Supabase project → Advisors → Security Advisor and fix anything flagged; every table in Table Editor should show "RLS enabled".',
    prompt: () => 'List every table in my Supabase public schema and tell me whether row level security is enabled on each one and which policies it has. For any table without RLS, or with policies that use USING (true) for insert, update or delete, write a migration that fixes it so users can only access their own rows.',
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────

const basename = p => p.slice(p.lastIndexOf('/') + 1);
const dirname = p => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

function lineLookup(content) {
  const starts = [0];
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1);
  return index => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
}

/** Show enough of a secret to find it, never enough to use it. */
export function mask(secret) {
  const shown = Math.min(8, Math.floor(secret.length / 3));
  return `${secret.slice(0, shown)}${'•'.repeat(8)} (${secret.length} chars)`;
}

function looksLikePlaceholder(token) {
  if (/your|example|placeholder|dummy|replace|redacted|xxxx|\.\.\./i.test(token)) return true;
  const body = token.replace(/^[a-z]+[_-](?:live_|proj-|ant-(?:api\d+-)?|secret_)?/i, '');
  return new Set(body).size < 8;
}

function decodeJwtPayload(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(part + '='.repeat((4 - (part.length % 4)) % 4)));
  } catch {
    return null;
  }
}

// Replace comments with spaces (newlines kept) so offsets and line numbers
// still line up with the original text. `line` is the line-comment opener.
function blankComments(text, line) {
  let out = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      out += c;
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"') {
      quote = c;
      out += c;
    } else if (text.startsWith(line, i)) {
      while (i < text.length && text[i] !== '\n') { out += ' '; i++; }
      if (i < text.length) out += '\n';
    } else if (text.startsWith('/*', i)) {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? text.length : end + 2;
      for (; i < stop; i++) out += text[i] === '\n' ? '\n' : ' ';
      i--;
    } else {
      out += c;
    }
  }
  return out;
}

// Text of the balanced (...) group starting at or after `from`, without the
// outer parentheses.
function readParens(text, from) {
  const open = text.indexOf('(', from);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) return text.slice(open + 1, i);
  }
  return null;
}

function buildContext(files, options) {
  const deps = new Set();
  for (const f of files) {
    if (basename(f.path) !== 'package.json') continue;
    try {
      const pkg = JSON.parse(f.content);
      for (const key of ['dependencies', 'devDependencies']) Object.keys(pkg[key] || {}).forEach(d => deps.add(d));
    } catch { /* not valid JSON, ignore */ }
  }
  return {
    deps,
    isNext: deps.has('next'),
    hasServerFramework: SERVER_FRAMEWORKS.some(d => deps.has(d)),
    usesSupabase: deps.has('@supabase/supabase-js') || deps.has('@supabase/ssr')
      || files.some(f => f.path.startsWith('supabase/')),
    tracked: options.tracked || null,
  };
}

// Code that is (probably) bundled for the browser. Used to raise severity.
function isClientCode(path, content, ctx) {
  if (!CODE_EXT.test(path)) return false;
  if (/^\s*['"]use client['"]/m.test(content)) return true;
  if (/^\s*['"]use server['"]/m.test(content) || /from\s+['"]server-only['"]/.test(content)) return false;
  if (SERVER_PATH.test(path) || CONFIG_FILE.test(path)) return false;
  if (ctx.isNext && /(?:^|\/)app\//.test(path)) return false; // server components by default
  return true;
}

// Code we are confident runs in the browser. Used by rules that would be
// noisy on server code (direct API calls, admin APIs).
function isDefinitelyClient(path, content, ctx) {
  if (!isClientCode(path, content, ctx)) return false;
  return /^\s*['"]use client['"]/m.test(content) || !ctx.hasServerFramework;
}

// ── Per-file rules ───────────────────────────────────────────────────────

const SECRET_PATTERNS = [
  { label: 'Stripe live secret key', envName: 'STRIPE_SECRET_KEY', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}/g },
  { label: 'Anthropic API key', envName: 'ANTHROPIC_API_KEY', re: /\bsk-ant-[A-Za-z0-9_-]{30,}/g },
  { label: 'OpenAI API key', envName: 'OPENAI_API_KEY', re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g },
  { label: 'AWS access key', envName: 'AWS_ACCESS_KEY_ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { label: 'GitHub token', envName: 'GITHUB_TOKEN', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/g },
  { label: 'Slack token', envName: 'SLACK_TOKEN', re: /\bxox[baprs]-[A-Za-z0-9-]{20,}/g },
  { label: 'Private key', envName: 'PRIVATE_KEY', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, literal: true },
];

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const SUPABASE_SECRET = /\bsb_secret_[A-Za-z0-9_-]{20,}/g;

function checkSecrets(file, ctx, add) {
  const name = basename(file.path);
  // A real .env file is where secrets belong; env-not-ignored covers leaks.
  if (ENV_FILE.test(name) && !ENV_EXAMPLE.test(name)) return;
  if (name === 'package.json' || name === '.gitignore') return;
  const client = isClientCode(file.path, file.content, ctx);
  for (const p of SECRET_PATTERNS) {
    for (const m of file.content.matchAll(p.re)) {
      if (!p.literal && looksLikePlaceholder(m[0])) continue;
      add('secret-in-code', client ? 'critical' : 'high', file, m.index,
        { label: p.label, envName: p.envName, client, evidence: p.literal ? m[0] : mask(m[0]) });
    }
  }
  for (const m of file.content.matchAll(JWT)) {
    if (decodeJwtPayload(m[0])?.role !== 'service_role') continue;
    add('supabase-service-key', client ? 'critical' : 'high', file, m.index,
      { kind: 'service_role', client, evidence: `${mask(m[0])}, role: service_role` });
  }
  for (const m of file.content.matchAll(SUPABASE_SECRET)) {
    if (looksLikePlaceholder(m[0])) continue;
    add('supabase-service-key', client ? 'critical' : 'high', file, m.index,
      { kind: 'secret', client, evidence: mask(m[0]) });
  }
}

const PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'NUXT_PUBLIC_', 'EXPO_PUBLIC_', 'REACT_APP_', 'VITE_', 'GATSBY_', 'PUBLIC_'];
const SENSITIVE_NAME = /SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES_URL|OPENAI|ANTHROPIC|GEMINI|GROQ|MISTRAL|REPLICATE|RESEND|SENDGRID|TWILIO_AUTH|AWS_SECRET/;

function checkPublicEnv(file, ctx, add) {
  const name = basename(file.path);
  const isEnv = ENV_FILE.test(name);
  if (!isEnv && !CODE_EXT.test(name)) return;
  const re = isEnv
    ? /^[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]*)[ \t]*=/gm
    : /(?:process\.env|import\.meta\.env)(?:\.([A-Z][A-Z0-9_]*)|\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\])/g;
  for (const m of file.content.matchAll(re)) {
    const varName = m[1] || m[2];
    const prefix = PUBLIC_PREFIXES.find(p => varName.startsWith(p));
    if (!prefix || !SENSITIVE_NAME.test(varName.slice(prefix.length))) continue;
    add('public-env-secret', 'critical', file, m.index,
      { name: varName, prefix, evidence: varName, dedupKey: varName });
  }
}

const LLM_HOSTS = [
  ['api.openai.com', 'OpenAI'], ['api.anthropic.com', 'Anthropic'],
  ['generativelanguage.googleapis.com', 'Google Gemini'], ['api.groq.com', 'Groq'],
  ['api.mistral.ai', 'Mistral'], ['openrouter.ai/api', 'OpenRouter'],
];

function checkLlmInBrowser(file, ctx, add) {
  if (!CODE_EXT.test(file.path)) return;
  for (const m of file.content.matchAll(/dangerouslyAllowBrowser\s*:\s*true/g)) {
    const provider = /anthropic/i.test(file.content) ? 'Anthropic' : 'OpenAI';
    add('llm-key-in-browser', 'critical', file, m.index, { provider, evidence: m[0] });
  }
  if (!isDefinitelyClient(file.path, file.content, ctx)) return;
  for (const [host, provider] of LLM_HOSTS) {
    const re = new RegExp(`https://${host.replace(/[./]/g, '\\$&')}`, 'g');
    for (const m of file.content.matchAll(re)) {
      add('llm-key-in-browser', 'high', file, m.index, { provider, evidence: m[0], dedupKey: `${file.path}:${host}` });
    }
  }
}

function checkSupabaseAdmin(file, ctx, add) {
  if (!isDefinitelyClient(file.path, file.content, ctx)) return;
  for (const m of file.content.matchAll(/\.auth\.admin\.\w+/g)) {
    add('supabase-admin-in-client', 'high', file, m.index, { evidence: m[0], dedupKey: file.path });
  }
}

function checkFirebaseRules(file, ctx, add) {
  const name = basename(file.path);
  if (name === 'database.rules.json') {
    for (const m of file.content.matchAll(/"\.(read|write)"\s*:\s*(?:true|"true")/g)) {
      const write = m[1] === 'write';
      add('firebase-open-rules', write ? 'critical' : 'medium', file, m.index,
        { kind: 'Realtime Database', ops: m[1], write, evidence: m[0] });
    }
    return;
  }
  if (!/\.rules$/.test(name)) return;
  const kind = /storage/i.test(name) ? 'Storage' : 'Firestore';
  const text = blankComments(file.content, '//');
  for (const m of text.matchAll(/\ballow\s+([a-z]+(?:\s*,\s*[a-z]+)*)\s*(?::\s*if\s+([^;]*))?;/gi)) {
    const ops = m[1].replace(/\s+/g, '');
    const cond = (m[2] || 'true').replace(/\s+/g, ' ').trim();
    const testMode = /request\.time\s*<\s*timestamp\.date\s*\(/.test(cond);
    if (!testMode && cond !== 'true') continue;
    const write = /write|create|update|delete/.test(ops);
    add('firebase-open-rules', testMode || write ? 'critical' : 'medium', file, m.index,
      { kind, ops: ops.replace(/,/g, ', '), write, testMode, evidence: m[0].replace(/\s+/g, ' ') });
  }
}

// ── Project-wide rules ───────────────────────────────────────────────────

function parseGitignore(content) {
  const rules = [];
  for (let raw of content.split(/\r?\n/)) {
    raw = raw.trim();
    if (!raw || raw.startsWith('#')) continue;
    const negate = raw.startsWith('!');
    let p = negate ? raw.slice(1) : raw.replace(/^\\/, '');
    const dirOnly = p.endsWith('/');
    if (dirOnly) p = p.slice(0, -1);
    const anchored = p.includes('/');
    p = p.replace(/^\//, '');
    let re = '';
    for (let i = 0; i < p.length; i++) {
      if (p.startsWith('**/', i)) { re += '(?:.*/)?'; i += 2; }
      else if (p.startsWith('**', i)) { re += '.*'; i++; }
      else if (p[i] === '*') re += '[^/]*';
      else if (p[i] === '?') re += '[^/]';
      else re += p[i].replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    rules.push({ negate, dirOnly, anchored, re: new RegExp(`^${re}$`) });
  }
  return rules;
}

function isIgnored(path, gitignores) {
  let ignored = false;
  for (const { dir, rules } of gitignores) {
    if (dir && !path.startsWith(`${dir}/`)) continue;
    const rel = dir ? path.slice(dir.length + 1) : path;
    const parts = rel.split('/');
    for (const rule of rules) {
      // A pattern can match the file itself or any directory above it.
      const hit = parts.some((_, i) => {
        if (rule.dirOnly && i === parts.length - 1) return false;
        return rule.re.test(rule.anchored ? parts.slice(0, i + 1).join('/') : parts[i]);
      });
      if (hit) ignored = !rule.negate;
    }
  }
  return ignored;
}

function checkEnvFiles(files, ctx, add) {
  const gitignores = files
    .filter(f => basename(f.path) === '.gitignore')
    .map(f => ({ dir: dirname(f.path), rules: parseGitignore(f.content) }))
    .sort((a, b) => a.dir.length - b.dir.length);
  for (const file of files) {
    const name = basename(file.path);
    if (!ENV_FILE.test(name) || ENV_EXAMPLE.test(name)) continue;
    const committed = ctx.tracked ? ctx.tracked.has(file.path) : false;
    if (!committed && isIgnored(file.path, gitignores)) continue;
    add('env-not-ignored', committed ? 'critical' : 'high', file, 0, { committed, evidence: file.path });
  }
}

const SQL_NAME = '((?:"?[A-Za-z_][\\w$]*"?\\.)?"?[A-Za-z_][\\w$]*"?)';

function tableKey(raw) {
  const parts = raw.replace(/"/g, '').toLowerCase().split('.');
  if (parts.length === 2 && parts[0] !== 'public') return null;
  return parts[parts.length - 1];
}

function trivialCondition(expr) {
  if (expr == null) return null;
  let e = expr.toLowerCase().replace(/\s+/g, '');
  while (e.startsWith('(') && readParens(e, 0)?.length === e.length - 2) e = e.slice(1, -1);
  e = e.replace(/\(select(auth\.\w+\(\))\)/g, '$1');
  if (e === 'true') return 'true';
  if (["auth.role()='authenticated'", 'auth.uid()isnotnull', 'auth.role()=\'authenticated\'::text'].includes(e)) return 'authenticated';
  return null;
}

function checkSupabaseSql(files, ctx, add) {
  const sqlFiles = files.filter(f => /\.sql$/i.test(f.path)).sort((a, b) => a.path.localeCompare(b.path));
  if (ctx.usesSupabase && sqlFiles.length === 0) {
    const pkg = files.find(f => basename(f.path) === 'package.json') || files[0];
    if (pkg) add('supabase-unverified', 'low', pkg, 0, { evidence: '@supabase/supabase-js without supabase/migrations' });
    return;
  }

  const tables = new Map(); // name -> { file, index, rls, disabledAt }
  for (const file of sqlFiles) {
    const sql = blankComments(file.content, '--');
    const create = new RegExp(`\\bcreate\\s+(?:(?:global\\s+|local\\s+)?(temp|temporary|unlogged)\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?${SQL_NAME}`, 'gi');
    const alter = new RegExp(`\\balter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${SQL_NAME}\\s+(enable|disable)\\s+row\\s+level\\s+security`, 'gi');
    const events = [];
    for (const m of sql.matchAll(create)) if (!/temp/i.test(m[1] || '')) events.push({ index: m.index, create: m[2] });
    for (const m of sql.matchAll(alter)) events.push({ index: m.index, alter: m[1], enable: m[2].toLowerCase() === 'enable' });
    events.sort((a, b) => a.index - b.index);
    for (const ev of events) {
      const key = tableKey(ev.create || ev.alter);
      if (!key) continue;
      if (ev.create) {
        if (!tables.has(key)) tables.set(key, { file, index: ev.index, rls: false });
      } else if (tables.has(key) || !ev.enable) {
        const t = tables.get(key) || { file, index: ev.index };
        t.rls = ev.enable;
        if (!ev.enable) Object.assign(t, { file, index: ev.index, disabled: true });
        tables.set(key, t);
      }
    }

    const policy = new RegExp(`\\bcreate\\s+policy\\s+("[^"]+"|\\w+)\\s+on\\s+${SQL_NAME}([^;]*)`, 'gi');
    for (const m of sql.matchAll(policy)) {
      const table = tableKey(m[2]);
      const rest = m[3];
      if (!table || /\bas\s+restrictive\b/i.test(rest)) continue;
      const command = (rest.match(/\bfor\s+(all|select|insert|update|delete)\b/i)?.[1] || 'all').toLowerCase();
      const roles = (rest.match(/\bto\s+([\w\s,"]+?)(?=\s+using\b|\s+with\s+check\b|\s*$)/i)?.[1] || 'public')
        .toLowerCase().split(',').map(r => r.trim().replace(/"/g, ''));
      const usingAt = rest.search(/\busing\s*\(/i);
      const checkAt = rest.search(/\bwith\s+check\s*\(/i);
      const conds = [usingAt, checkAt].filter(i => i !== -1).map(i => trivialCondition(readParens(rest, i)));
      const trivial = conds.includes('true') ? 'true' : conds.includes('authenticated') ? 'authenticated' : null;
      if (!trivial) continue;
      const anyone = trivial === 'true' && roles.some(r => r === 'anon' || r === 'public');
      const who = anyone ? 'anyone' : 'any signed-in user';
      const write = command !== 'select';
      const severity = !write ? 'low' : command === 'insert' ? 'medium' : anyone ? 'critical' : 'high';
      const verb = { all: 'read and change', select: 'read', insert: 'insert into', update: 'update', delete: 'delete' }[command];
      add('supabase-open-policy', severity, file, m.index, {
        policy: m[1].replace(/"/g, ''), table, who, write, verb, trivial,
        evidence: m[0].replace(/\s+/g, ' ').slice(0, 160),
      });
    }
  }

  for (const [table, t] of tables) {
    if (t.rls) continue;
    add('supabase-rls-missing', 'critical', t.file, t.index, { table, disabled: !!t.disabled, evidence: table });
  }
}

// ── Entry point ──────────────────────────────────────────────────────────

const PER_FILE = [checkSecrets, checkPublicEnv, checkLlmInBrowser, checkSupabaseAdmin, checkFirebaseRules];

/**
 * Scan a project.
 * @param {{path: string, content: string}[]} files
 * @param {{tracked?: Set<string>}} [options] tracked: paths committed to git, if known
 */
export function scanProject(files, options = {}) {
  const ctx = buildContext(files, options);
  const lines = new Map();
  const seen = new Map();
  const findings = [];

  const add = (ruleId, severity, file, index, vars) => {
    if (!lines.has(file.path)) lines.set(file.path, lineLookup(file.content));
    const line = lines.get(file.path)(index);
    const sourceLine = file.content.split('\n', line)[line - 1] || '';
    if (sourceLine.includes('sec-check-ignore')) return;
    if (vars.dedupKey) {
      const key = `${ruleId}:${vars.dedupKey}`;
      if (seen.has(key)) { seen.get(key).occurrences++; return; }
    }
    const rule = RULES[ruleId];
    const v = { ...vars, file: file.path, line };
    const finding = {
      rule: ruleId, severity, file: file.path, line,
      title: rule.title(v), evidence: vars.evidence,
      why: rule.why(v), fix: rule.fix(v), prompt: rule.prompt(v),
      occurrences: 1,
    };
    if (vars.dedupKey) seen.set(`${ruleId}:${vars.dedupKey}`, finding);
    findings.push(finding);
  };

  for (const file of files) {
    if (file.content.slice(0, 300).includes('sec-check-ignore-file')) continue;
    for (const check of PER_FILE) check(file, ctx, add);
  }
  checkEnvFiles(files, ctx, add);
  checkSupabaseSql(files, ctx, add);

  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
    || a.file.localeCompare(b.file) || a.line - b.line);
  const summary = Object.fromEntries(SEVERITIES.map(s => [s, findings.filter(f => f.severity === s).length]));
  return { findings, summary, grade: grade(summary), filesScanned: files.length };
}

export function grade(summary) {
  if (summary.critical) return 'F';
  if (summary.high) return 'D';
  if (summary.medium) return 'C';
  if (summary.low) return 'B';
  return 'A';
}
