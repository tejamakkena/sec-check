// sec-check-ignore-file: tests are full of intentionally insecure fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanProject, isScannable, mask, RULES } from '../rules.js';
import { demoProject, fakeKeys, fakeJwt } from '../demo.js';

const scan = (files, options) => scanProject(files, options).findings;
const rulesOf = findings => findings.map(f => f.rule);
const viteApp = (...files) => [
  { path: 'package.json', content: JSON.stringify({ dependencies: { react: '1', vite: '1' } }) },
  { path: '.gitignore', content: '.env*\n' },
  ...files,
];

test('demo project triggers every major rule', () => {
  const { findings, grade, summary } = scanProject(demoProject());
  const rules = new Set(rulesOf(findings));
  for (const id of ['secret-in-code', 'supabase-service-key', 'public-env-secret', 'env-not-ignored',
    'supabase-rls-missing', 'supabase-open-policy', 'firebase-open-rules', 'llm-key-in-browser',
    'supabase-admin-in-client']) {
    assert.ok(rules.has(id), `expected ${id}`);
  }
  assert.equal(grade, 'F');
  assert.ok(summary.critical >= 5);
  for (const f of findings) {
    assert.ok(f.title && f.why && f.fix && f.prompt, `${f.rule} has full copy`);
    assert.ok(f.line >= 1);
  }
});

test('demo: RLS findings name the right tables only', () => {
  const findings = scan(demoProject());
  const rls = findings.filter(f => f.rule === 'supabase-rls-missing').map(f => f.title);
  assert.deepEqual(rls, ['Row-level security is off for table "messages"']);
  const policies = findings.filter(f => f.rule === 'supabase-open-policy');
  assert.deepEqual(policies.map(p => [p.severity, p.title]), [
    ['critical', 'Policy "Anyone can update orders" lets anyone update any row in "orders"'],
    ['high', 'Policy "Logged in users can delete orders" lets any signed-in user delete any row in "orders"'],
    ['low', 'Policy "Posts are public" lets anyone read every row in "posts"'],
  ]);
});

test('never prints a full secret', () => {
  for (const f of scan(demoProject())) {
    for (const secret of Object.values(fakeKeys)) {
      for (const text of [f.evidence, f.title, f.why, f.fix, f.prompt]) {
        assert.ok(!String(text).includes(secret), `${f.rule} leaks a secret`);
      }
    }
  }
  assert.match(mask(['sk', 'live', 'abcdefghijklmnopqrstuvwxyz'].join('_')), /^sk_live_•+ \(34 chars\)$/);
});

test('secrets: browser code is critical, server code is high', () => {
  const findings = scan(viteApp(
    { path: 'src/App.tsx', content: `const k = "${fakeKeys.stripe}";` },
    { path: 'supabase/functions/pay/index.ts', content: `const k = "${fakeKeys.stripe}";` },
  )).filter(f => f.rule === 'secret-in-code');
  assert.deepEqual(findings.map(f => [f.file, f.severity]), [
    ['src/App.tsx', 'critical'],
    ['supabase/functions/pay/index.ts', 'high'],
  ]);
});

test('secrets: placeholders, anon keys and real .env files are not flagged', () => {
  const findings = scan(viteApp(
    { path: 'src/a.ts', content: `const k = "${['sk', 'live', 'x'.repeat(28)].join('_')}";\nconst o = "${['sk', 'proj', 'your-openai-key-goes-here-please-replace'].join('-')}";` },
    { path: 'src/client.ts', content: `createClient(url, "${fakeKeys.anon}")` },
    { path: '.env.local', content: `SUPABASE_SERVICE_ROLE_KEY=${fakeKeys.serviceRole}\nSTRIPE_SECRET_KEY=${fakeKeys.stripe}\n` },
  ));
  assert.deepEqual(findings, []);
});

test('secrets: .env.example with a real-looking key is flagged', () => {
  const findings = scan(viteApp({ path: '.env.example', content: `STRIPE_SECRET_KEY=${fakeKeys.stripe}\n` }));
  assert.deepEqual(rulesOf(findings), ['secret-in-code']);
});

test('secrets: Anthropic keys are not double-reported as OpenAI', () => {
  const key = ['sk', 'ant', 'api03', 'Zq8Lm2Np4Rt6Vx8Bz1Cd3Fg5Hj7Kl9Mn0Pq2Rs4Tu6Wy8'].join('-');
  const findings = scan(viteApp({ path: 'server/ai.py', content: `KEY = "${key}"` }));
  assert.deepEqual(findings.map(f => f.title), ['Anthropic API key hardcoded in source code']);
});

test('service_role JWT detected by decoding the payload', () => {
  const findings = scan(viteApp({ path: 'src/admin.ts', content: `const k = "${fakeJwt('service_role')}"` }));
  assert.deepEqual(findings.map(f => [f.rule, f.severity]), [['supabase-service-key', 'critical']]);
});

test('public env: secret names with public prefixes, deduplicated', () => {
  const findings = scan(viteApp(
    { path: 'src/a.ts', content: 'import.meta.env.VITE_OPENAI_API_KEY; import.meta.env.VITE_SUPABASE_ANON_KEY;' },
    { path: 'src/b.ts', content: 'import.meta.env.VITE_OPENAI_API_KEY' },
    { path: 'app/page.tsx', content: 'process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY; process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY; process.env.STRIPE_SECRET_KEY' },
  ));
  const pub = findings.filter(f => f.rule === 'public-env-secret');
  assert.deepEqual(pub.map(f => [f.evidence, f.occurrences]), [
    ['NEXT_PUBLIC_STRIPE_SECRET_KEY', 1],
    ['VITE_OPENAI_API_KEY', 2],
  ]);
});

test('env files: gitignore patterns and git tracking', () => {
  const base = [{ path: '.env', content: 'A=1' }, { path: 'web/.env.local', content: 'A=1' }];
  assert.equal(scan([...base, { path: '.gitignore', content: 'node_modules\n' }]).length, 2);
  assert.equal(scan([...base, { path: '.gitignore', content: '.env*\n!.env.example\n' }]).length, 0);
  assert.equal(scan([...base, { path: '.gitignore', content: '/.env\n' }]).length, 1);
  assert.equal(scan([...base, { path: '.gitignore', content: '.env\n' }, { path: 'web/.gitignore', content: '*.local\n' }]).length, 0);
  assert.equal(scan([...base, { path: '.gitignore', content: '.env*\n!.env\n' }]).length, 1);
  const committed = scan([...base, { path: '.gitignore', content: '.env*\n' }], { tracked: new Set(['.env']) });
  assert.deepEqual(committed.map(f => [f.file, f.severity]), [['.env', 'critical']]);
});

test('supabase: RLS tracked across migrations, schemas and comments', () => {
  const findings = scan([
    { path: 'supabase/migrations/1_a.sql', content: 'CREATE TABLE IF NOT EXISTS "public"."Notes" (id int);\ncreate table private.secrets (id int);\ncreate temp table scratch (id int);\n-- alter table notes enable row level security;\ncreate table todos (id int);' },
    { path: 'supabase/migrations/2_b.sql', content: 'ALTER TABLE ONLY public.notes ENABLE ROW LEVEL SECURITY;\nalter table todos enable row level security;\nalter table todos disable row level security;' },
  ]);
  assert.deepEqual(findings.map(f => [f.title, f.file, f.line]), [
    ['Row-level security is disabled on "todos"', 'supabase/migrations/2_b.sql', 3],
  ]);
});

test('supabase: ownership policies are fine, trivial ones are not', () => {
  const sql = `create table t (id int, user_id uuid);\nalter table t enable row level security;\n` +
    `create policy own on t for all to authenticated using ((select auth.uid()) = user_id);\n` +
    `create policy "contact form" on t for insert to anon with check (true);\n` +
    `create policy strict on t as restrictive for all using (true);\n` +
    `create policy "edit" on t for update to authenticated using (true) with check (auth.uid() = user_id);\n` +
    `create policy "any user" on t for all using ((auth.uid() IS NOT NULL));`;
  const findings = scan([{ path: 'supabase/migrations/1.sql', content: sql }]);
  assert.deepEqual(findings.map(f => [f.severity, f.title]), [
    ['high', 'Policy "edit" lets any signed-in user update any row in "t"'],
    ['high', 'Policy "any user" lets any signed-in user read and change any row in "t"'],
    ['medium', 'Policy "contact form" lets anyone insert into any row in "t"'],
  ]);
});

test('supabase: project with no migrations gets a manual-check reminder', () => {
  const findings = scan([{ path: 'package.json', content: JSON.stringify({ dependencies: { '@supabase/supabase-js': '2' } }) }]);
  assert.deepEqual(findings.map(f => [f.rule, f.severity]), [['supabase-unverified', 'low']]);
});

test('firebase: open, test-mode and safe rules', () => {
  const findings = scan([
    { path: 'firestore.rules', content: `match /public/{id} {\n  allow read: if true;\n}\nmatch /users/{uid} {\n  // allow read, write: if true;\n  allow read, write: if request.auth != null && request.auth.uid == uid;\n}\nmatch /logs/{id} { allow create; }` },
    { path: 'database.rules.json', content: '{ "rules": { ".read": "auth != null", ".write": true } }' },
  ]);
  assert.deepEqual(findings.map(f => [f.severity, f.title]), [
    ['critical', 'Firebase Realtime Database rules allow write for everyone'],
    ['critical', 'Firebase Firestore rules allow create for everyone'],
    ['medium', 'Firebase Firestore rules allow read for everyone'],
  ]);
});

test('LLM calls: flagged in browser code, not in server routes or Next server components', () => {
  const next = { path: 'package.json', content: JSON.stringify({ dependencies: { next: '15' } }) };
  const findings = scan([
    next,
    { path: 'app/page.tsx', content: 'await fetch("https://api.openai.com/v1/chat/completions")' },
    { path: 'app/api/chat/route.ts', content: 'await fetch("https://api.anthropic.com/v1/messages")' },
    { path: 'components/Chat.tsx', content: '"use client";\nawait fetch("https://api.openai.com/v1/x"); await fetch("https://api.openai.com/v1/y")' },
  ]);
  assert.deepEqual(findings.map(f => [f.file, f.line, f.occurrences]), [['components/Chat.tsx', 2, 2]]);
});

test('sec-check-ignore comments suppress a line or a whole file', () => {
  const findings = scan(viteApp(
    { path: 'src/a.ts', content: `const k = "${fakeKeys.stripe}"; // sec-check-ignore: test fixture\nconst j = "${fakeKeys.stripe}";` },
    { path: 'src/b.ts', content: `// sec-check-ignore-file\nconst k = "${fakeKeys.stripe}";` },
  ));
  assert.deepEqual(findings.map(f => [f.file, f.line]), [['src/a.ts', 2]]);
});

test('isScannable skips dependencies, builds and lockfiles', () => {
  assert.ok(isScannable('src/App.tsx'));
  assert.ok(isScannable('.env.production'));
  assert.ok(isScannable('supabase/migrations/1.sql'));
  assert.ok(isScannable('firestore.rules'));
  assert.ok(!isScannable('node_modules/x/index.js'));
  assert.ok(!isScannable('web/.next/server/page.js'));
  assert.ok(!isScannable('package-lock.json'));
  assert.ok(!isScannable('public/logo.png'));
  assert.ok(!isScannable('assets/app.min.js'));
});

test('every rule has complete copy', () => {
  for (const [id, rule] of Object.entries(RULES)) {
    for (const key of ['name', 'summary', 'title', 'why', 'fix', 'prompt']) assert.ok(rule[key], `${id}.${key}`);
  }
});
