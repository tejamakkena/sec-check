// sec-check-ignore-file: intentionally insecure demo fixtures.
// A small, deliberately insecure "AI-built" project used by the "Try a demo"
// button and the tests. Every key is generated at runtime from a fixed seed so
// nothing that looks like a real credential is ever committed to this repo.

function fake(length, seed) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let s = seed, out = '';
  for (let i = 0; i < length; i++) {
    s = (s * 1103515245 + 12345) % 2147483648;
    out += chars[s % chars.length];
  }
  return out;
}

const b64url = obj => btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function fakeJwt(role, seed = 7) {
  const header = b64url({ alg: 'HS256', typ: 'JWT' });
  const payload = b64url({ iss: 'supabase', ref: 'demo', role, iat: 1700000000, exp: 2000000000 });
  return `${header}.${payload}.${fake(43, seed)}`;
}

export const fakeKeys = {
  stripe: ['sk', 'live', fake(32, 11)].join('_'),
  openai: ['sk', 'proj', fake(48, 13)].join('-'),
  anon: fakeJwt('anon', 3),
  serviceRole: fakeJwt('service_role', 5),
};

export function demoProject() {
  const k = fakeKeys;
  return [
    {
      path: 'package.json',
      content: JSON.stringify({
        name: 'my-lovable-app',
        dependencies: { react: '^18.3.1', '@supabase/supabase-js': '^2.45.0', openai: '^4.56.0' },
        devDependencies: { vite: '^5.4.0' },
      }, null, 2),
    },
    { path: '.gitignore', content: 'node_modules\ndist\n' },
    {
      path: '.env',
      content: `VITE_SUPABASE_URL=https://demo.supabase.co\nVITE_SUPABASE_ANON_KEY=${k.anon}\nVITE_OPENAI_API_KEY=${k.openai}\n`,
    },
    {
      path: 'src/integrations/supabase/client.ts',
      content: `import { createClient } from '@supabase/supabase-js';\n\n// The anon key is meant to be public. RLS is what protects the data.\nexport const supabase = createClient('https://demo.supabase.co', '${k.anon}');\n`,
    },
    {
      path: 'src/lib/ai.ts',
      content: `import OpenAI from 'openai';\n\nexport const openai = new OpenAI({\n  apiKey: import.meta.env.VITE_OPENAI_API_KEY,\n  dangerouslyAllowBrowser: true,\n});\n`,
    },
    {
      path: 'src/pages/Checkout.tsx',
      content: `const STRIPE_KEY = '${k.stripe}';\n\nexport default function Checkout() {\n  return <button onClick={() => pay(STRIPE_KEY)}>Pay</button>;\n}\n`,
    },
    {
      path: 'src/pages/Admin.tsx',
      content: `import { createClient } from '@supabase/supabase-js';\n\nconst admin = createClient('https://demo.supabase.co', '${k.serviceRole}');\n\nexport async function loadUsers() {\n  const { data } = await admin.auth.admin.listUsers();\n  return data.users;\n}\n`,
    },
    {
      path: 'supabase/migrations/20250101000000_init.sql',
      content: `-- Profiles: done right\ncreate table public.profiles (\n  id uuid primary key references auth.users,\n  display_name text\n);\nalter table public.profiles enable row level security;\ncreate policy "Users manage their own profile" on public.profiles\n  for all using (auth.uid() = id) with check (auth.uid() = id);\n\n-- Messages: RLS forgotten\ncreate table public.messages (\n  id bigint generated always as identity primary key,\n  user_id uuid references auth.users,\n  body text\n);\n\n-- Orders: RLS on, but the policy lets anyone edit anything\ncreate table public.orders (\n  id bigint generated always as identity primary key,\n  user_id uuid references auth.users,\n  total numeric\n);\nalter table public.orders enable row level security;\ncreate policy "Anyone can update orders" on public.orders\n  for update using (true);\ncreate policy "Logged in users can delete orders" on public.orders\n  for delete to authenticated using (auth.role() = 'authenticated');\n\n-- Posts: public read is intended\ncreate table public.posts (id bigint primary key, title text);\nalter table public.posts enable row level security;\ncreate policy "Posts are public" on public.posts for select using (true);\n`,
    },
    {
      path: 'firestore.rules',
      content: `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(2026, 1, 1);\n    }\n  }\n}\n`,
    },
  ];
}
