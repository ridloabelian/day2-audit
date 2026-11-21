# day2-audit

[![CI](https://github.com/ridloabelian/day2-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ridloabelian/day2-audit/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

Fast, offline **Day-2 production readiness CLI scanner** for weekend and vibe-coded web & AI repositories.

Shipped your MVP with Cursor, Claude, or v0? `day2-audit` audits your codebase in milliseconds — with **zero external paid API calls** — to catch the security, cost-runaway, API safety, reliability, and operational gaps that break real-world production launches.

---

## Features

- **Zero-API Offline Analysis**: Comment-aware lexical + config + route scanner runs locally in milliseconds.
- **Stack Auto-Detection**: Automatically detects **Next.js** (App/Pages Router), **React**, **Node APIs** (Express, Fastify, Hono, NestJS), **Supabase**, **Prisma**, **Drizzle**, **Cloudflare Workers**, **Docker**, **Python / FastAPI**, and AI SDKs (**OpenAI**, **Anthropic**, **Vercel AI SDK**, **Google Gemini**, **LangChain**).
- **15 Concrete Day-2 Rules across 5 Categories**: Scoring `0–100`, severity breakdown (`CRITICAL` / `HIGH` / `MEDIUM`), exact `file:line` pointers, and copy-paste remediation snippets.
- **Actionable Output Modes**:
  - Rich colorized terminal scorecard
  - `--json` for CI pipelines & dashboards
  - `--markdown` (`DAY2_REPORT.md`) for pull request reviews & GitHub Actions artifacts
  - `--prompt` to generate a ready-to-paste remediation prompt for your AI coding agent

---

## Quickstart

Requires **Node.js 22+**.

```bash
# Install dependencies and build from source
npm install
npm run build

# Scan the included vulnerable weekend app fixture
node dist/cli.js scan fixtures/vulnerable-vibe-app

# Scan the included hardened reference app
node dist/cli.js scan fixtures/hardened-app --fail-on medium
```

Or install globally / run directly when published:

```bash
npx day2-audit scan .
```

---

## CLI Usage

```text
Usage: day2-audit [options] [command]

Commands:
  scan [options] [target]  Audit a repository directory for Day-2 production readiness risks (default)
  rules [options]          List all built-in Day-2 readiness rules
```

### Options for `scan`

| Flag | Description |
| --- | --- |
| `--json` | Output structured JSON (`ScanResult`) to stdout |
| `--markdown [file]` | Write Markdown report (default `DAY2_REPORT.md`, or `-` for stdout) |
| `--prompt [file]` | Output a ready-to-paste AI coding agent remediation prompt (or write to file) |
| `--fail-on <level>` | Exit with code `1` when findings meet threshold: `critical`, `high`, `medium`, or `none` |
| `--category <id>` | Run only one category (`auth-data`, `cost-abuse`, `api-safety`, `reliability`, `ops-hygiene`) |
| `--ignore-rule <ids>` | Comma-separated rule IDs to ignore (e.g. `DAY2-OPS-001,DAY2-API-002`) |

---

## Built-In Day-2 Checkers (15 Rules)

### 1. Auth & Data Exposure (`auth-data`)
| Rule ID | Severity | Check |
| --- | --- | --- |
| `DAY2-AUTH-001` | `CRITICAL` | Supabase / SQL migrations missing `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` |
| `DAY2-AUTH-002` | `CRITICAL` | State-mutating HTTP routes (`POST`/`PUT`/`PATCH`/`DELETE`) missing auth checks |
| `DAY2-AUTH-003` | `CRITICAL` | Leaked secrets in `NEXT_PUBLIC_*` / `VITE_*`, git-tracked `.env` files, or hardcoded API keys |

### 2. Cost & Abuse Protection (`cost-abuse`)
| Rule ID | Severity | Check |
| --- | --- | --- |
| `DAY2-COST-001` | `HIGH` | OpenAI / Anthropic / Vercel AI SDK calls missing `max_tokens` or `timeout` / `AbortSignal` |
| `DAY2-COST-002` | `HIGH` | Public API routes missing rate-limiting middleware |
| `DAY2-COST-003` | `HIGH` | Unbounded loops (`while (true)`, `for (;;)`, `while True:`) calling async/AI services |

### 3. API & Webhook Safety (`api-safety`)
| Rule ID | Severity | Check |
| --- | --- | --- |
| `DAY2-API-001` | `CRITICAL` | Webhook endpoints missing signature verification (`constructEvent`, Svix, HMAC) |
| `DAY2-API-002` | `MEDIUM` | Permissive wildcard CORS (`*` or bare `cors()`) |
| `DAY2-API-003` | `HIGH` | Unsafe raw SQL string interpolation (`$queryRawUnsafe`, template strings, Python f-strings) |

### 4. Reliability & Resilience (`reliability`)
| Rule ID | Severity | Check |
| --- | --- | --- |
| `DAY2-REL-001` | `MEDIUM` | Missing HTTP healthcheck route (`/health`, `/api/health`) or Docker `HEALTHCHECK` |
| `DAY2-REL-002` | `MEDIUM` | Missing error boundary (`error.tsx`, `ErrorBoundary`) or global API error middleware |
| `DAY2-REL-003` | `HIGH` | Swallowed errors (`catch {}` / `except: pass`) or Node servers lacking `unhandledRejection` |

### 5. Ops & Dependency Hygiene (`ops-hygiene`)
| Rule ID | Severity | Check |
| --- | --- | --- |
| `DAY2-OPS-001` | `HIGH` | Hardcoded `http://localhost` / `127.0.0.1` URLs without environment fallback |
| `DAY2-OPS-002` | `MEDIUM` | Missing lockfile or unpinned `*` / `latest` dependencies |
| `DAY2-OPS-003` | `MEDIUM` | Missing DB migration workflow/backup scripts or destructive `db push` in `build` scripts |

---

## Sample Output

Running `node dist/cli.js scan fixtures/vulnerable-vibe-app`:

```text
day2-audit v0.1.0  •  Scanned vulnerable-vibe-app in 28ms
Stack: Next.js (App Router), React, Supabase, Prisma, Docker  |  AI SDKs: OpenAI
────────────────────────────────────────────────────────────────────────────
Day-2 Readiness Score: 0/100  [░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  Grade F  (CRITICAL RISK)
Findings: 6 CRITICAL  •  6 HIGH  •  8 MEDIUM  (20 total)

Category Scorecard
  Auth & Data Exposure          25/100   5 issues
  Cost & Abuse Protection       76/100   3 issues
  API & Webhook Safety          73/100   3 issues
  Reliability & Resilience      80/100   4 issues
  Ops & Dependency Hygiene      76/100   5 issues
```

---

## GitHub Actions CI Integration

```yaml
name: Day-2 Readiness Audit
on: [pull_request, push]

jobs:
  day2-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx day2-audit scan . --markdown DAY2_REPORT.md --fail-on critical
```

---

## Programmatic API

```ts
import { scanRepository, renderMarkdownReport } from 'day2-audit';

const result = await scanRepository('./my-app');
console.log(`Score: ${result.score}/100 (${result.grade})`);
const markdown = renderMarkdownReport(result);
```

---

## Development & Tests

```bash
npm run typecheck
npm run build
npm test
```

## License

MIT
