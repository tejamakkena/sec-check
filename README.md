# sec-check

https://tejamakkena.github.io/sec-check/

Two things live here:

- **[Personal Digital Security Blueprint](https://tejamakkena.github.io/sec-check/)**: a visual guide to protecting your identity, money, devices and data.
- **[sec-check scanner](https://tejamakkena.github.io/sec-check/scan.html)**: a security check for apps built with AI tools such as Lovable, Bolt, Cursor, Replit and v0.

## sec-check scanner

AI app builders make shipping easy, and they tend to ship the same few security mistakes. sec-check reads your project's source code, finds them, and gives you a plain-English explanation plus a fix prompt you can paste back into your AI tool.

It runs on your machine: in the browser (nothing is uploaded) or as a zero-dependency CLI. It reads code only and never connects to your database or website.

### What it checks

| Check | Example |
| --- | --- |
| Secret keys in source code | Stripe live keys, OpenAI / Anthropic keys, AWS, GitHub and Slack tokens, private keys |
| Supabase service_role / secret key exposed | A `service_role` JWT (detected by decoding it) or `sb_secret_` key outside server-only env files |
| Secrets in browser-exposed env vars | `VITE_OPENAI_API_KEY`, `NEXT_PUBLIC_STRIPE_SECRET_KEY` |
| `.env` files that can end up in git | `.env` committed, or not covered by `.gitignore` |
| Supabase tables without row-level security | `create table` in the public schema with no `enable row level security` |
| Supabase policies that let anyone in | `using (true)` on update/delete, or "any logged-in user" checks such as `auth.role() = 'authenticated'` |
| Open Firebase rules | `allow read, write: if true`, test-mode `request.time <` rules, open `database.rules.json` |
| AI APIs called from the browser | `dangerouslyAllowBrowser: true`, `fetch('https://api.openai.com/…')` in frontend code |
| Supabase admin API in browser code | `supabase.auth.admin.*` in the frontend |

Severity depends on where a problem is: a key in browser code is **critical** (every visitor can read it), while the same key in server code is **high** (anyone with repo access can read it). Secrets are always masked in output.

### Use it

**Browser:** open [scan.html](https://tejamakkena.github.io/sec-check/scan.html), then pick or drop your project folder, or try the built-in demo project.

**CLI** (Node 18+, no install):

```sh
npx github:tejamakkena/sec-check ./my-app
npx github:tejamakkena/sec-check ./my-app --json            # machine-readable
npx github:tejamakkena/sec-check ./my-app --fail-on=critical # CI gate
```

It exits with code 1 when a finding is at or above `--fail-on` (default `high`). Inside a git repo, the CLI also checks whether `.env` files are actually committed.

**GitHub Actions:**

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: 20 }
- run: npx --yes github:tejamakkena/sec-check . --no-prompts
```

To silence a finding you have reviewed, put `sec-check-ignore` in a comment on that line, or `sec-check-ignore-file` near the top of a file.

### Limits

sec-check is static analysis with heuristics. It can't see tables, policies or rules you changed in a dashboard, and a clean result is not a guarantee. If you use Supabase, also run **Advisors → Security Advisor** in your project dashboard.

### Development

```sh
npm test                            # node:test, no dependencies
node scanner/cli.js path/to/project
python3 -m http.server              # then open http://localhost:8000/scan.html
```

`scanner/rules.js` holds every rule and is shared by the CLI (`scanner/cli.js`) and the browser page (`scan.html`). The CLI reads `.git/index` itself (`scanner/git-index.js`) instead of running git, so scanning an untrusted project can never trigger that project's git config. `scanner/demo.js` is a deliberately insecure sample project. Its fake keys are generated at runtime so no credential-shaped strings are committed.
