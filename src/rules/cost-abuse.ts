import {
  extractBalancedBlock,
  extractCallExpressions,
  extractHttpRoutes,
  extractPythonIndentedBlock,
  getLineSnippet,
  offsetToLine,
  stripCommentsKeepLines,
} from '../scanner/code-analyzer.js';
import { CATEGORIES, type Finding, type Rule, type ScanContext } from '../types.js';

const CATEGORY = 'cost-abuse' as const;
const CATEGORY_LABEL = CATEGORIES[CATEGORY];

const LLM_CALL_RE =
  /\b(?:[a-zA-Z0-9_$]+\.(?:chat\.completions|responses|messages)\.(?:create|stream)|generateText|streamText|generateObject|streamObject)\s*\(/;

const MAX_TOKEN_RE =
  /\b(?:max_tokens|maxTokens|max_completion_tokens|maxOutputTokens)\b/;

const TIMEOUT_RE =
  /\b(?:timeout|abortSignal|signal)\b|AbortSignal\.timeout/;

const RATE_LIMIT_RE =
  /\b(?:ratelimit|rateLimit|rateLimiter|limiter|upstash|Ratelimit|slowapi|RATE_LIMITER|limitByIp|checkRateLimit)\b|express-rate-limit|@fastify\/rate-limit|hono-rate-limiter/i;

const RATE_EXEMPT_ROUTE_RE =
  /\/(?:health|healthz|ready|live|ping|webhooks?)(?:\/|$)/i;

const ASYNC_IO_RE =
  /\bawait\b|\bfetch\s*\(|\.create\s*\(|\baxios\.|\brequests\.|\bhttpx\.|\bprisma\.|\bsupabase\./;

const BOUND_GUARD_RE =
  /\b(?:maxSteps|MAX_STEPS|maxIterations|MAX_ITERATIONS|maxRetries|MAX_RETRIES|maxAttempts|MAX_ATTEMPTS|attempts|retries|AbortSignal|signal\.aborted)\b/;

function hasGlobalRateLimitMiddleware(ctx: ScanContext): boolean {
  const middlewareFiles = [
    'middleware.ts',
    'middleware.js',
    'src/middleware.ts',
    'src/middleware.js',
  ];
  for (const rel of middlewareFiles) {
    const f = ctx.fileMap.get(rel);
    if (f && RATE_LIMIT_RE.test(stripCommentsKeepLines(f.content, 'js'))) {
      return true;
    }
  }
  return false;
}

export const costAbuseRules: Rule[] = [
  {
    id: 'DAY2-COST-001',
    title: 'LLM SDK Call Missing max_tokens or Timeout',
    category: CATEGORY,
    severity: 'HIGH',
    description:
      'OpenAI, Anthropic, or Vercel AI SDK calls without token caps or timeouts can hang connections and trigger runaway billing.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];

      for (const file of ctx.files) {
        if (file.isTest) continue;
        if (!['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py'].includes(file.ext)) {
          continue;
        }

        const lang = file.ext === '.py' ? 'py' : 'js';
        const stripped = stripCommentsKeepLines(file.content, lang);
        const clientHasTimeout =
          /new\s+(?:OpenAI|Anthropic)\s*\(\s*\{[^}]*\btimeout\s*:/s.test(stripped) ||
          /(?:OpenAI|Anthropic)\s*\([^)]*\btimeout\s*=/s.test(stripped);

        const calls = extractCallExpressions(stripped, LLM_CALL_RE);
        for (const call of calls) {
          const hasTokens = MAX_TOKEN_RE.test(call.argsText);
          const hasTimeout = clientHasTimeout || TIMEOUT_RE.test(call.argsText);

          if (!hasTokens || !hasTimeout) {
            const missing: string[] = [];
            if (!hasTokens) missing.push('max_tokens');
            if (!hasTimeout) missing.push('timeout / AbortSignal');
            findings.push({
              ruleId: 'DAY2-COST-001',
              title: 'LLM SDK Call Missing max_tokens or Timeout',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'HIGH',
              file: file.relPath,
              line: call.startLine,
              message: `LLM call "${call.callee}" is missing ${missing.join(' and ')}.`,
              snippet: getLineSnippet(file.lines, call.startLine),
              remediation: `Bound generation cost and latency on ${call.callee}:\n{ model: 'gpt-4o', max_tokens: 1024, messages }, { timeout: 15_000, signal: AbortSignal.timeout(15_000) }`,
            });
          }
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-COST-002',
    title: 'Public API Endpoint Missing Rate Limiting',
    category: CATEGORY,
    severity: 'HIGH',
    description:
      'HTTP route handlers without rate-limiting middleware are vulnerable to credential stuffing, scraping, and token-drain abuse.',
    check(ctx: ScanContext): Finding[] {
      if (hasGlobalRateLimitMiddleware(ctx)) return [];

      const findings: Finding[] = [];
      const workerEntries = new Set(
        ctx.stack.stacks.includes('cloudflare-workers')
          ? ['src/index.ts', 'src/index.js']
          : [],
      );

      for (const file of ctx.files) {
        if (file.isTest) continue;
        const routes = extractHttpRoutes(file, workerEntries.has(file.relPath));
        if (routes.length === 0) continue;

        const lang = file.ext === '.py' ? 'py' : 'js';
        const fileStripped = stripCommentsKeepLines(file.content, lang);
        const fileHasLimiter = RATE_LIMIT_RE.test(fileStripped);

        for (const route of routes) {
          if (RATE_EXEMPT_ROUTE_RE.test(route.routePath)) continue;
          if (RATE_EXEMPT_ROUTE_RE.test(`/${file.relPath}`)) continue;
          if (fileHasLimiter || RATE_LIMIT_RE.test(route.handlerBody)) continue;

          findings.push({
            ruleId: 'DAY2-COST-002',
            title: 'Public API Endpoint Missing Rate Limiting',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'HIGH',
            file: file.relPath,
            line: route.startLine,
            message: `${route.method} ${route.routePath} does not enforce rate limiting.`,
            snippet: getLineSnippet(file.lines, route.startLine),
            remediation: `Apply per-IP/user rate limiting (e.g., @upstash/ratelimit or express-rate-limit):\nconst { success } = await ratelimit.limit(ip);\nif (!success) return Response.json({ error: 'Too Many Requests' }, { status: 429 });`,
          });
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-COST-003',
    title: 'Unbounded Loop Invoking External or AI Services',
    category: CATEGORY,
    severity: 'HIGH',
    description:
      'Infinite loops (while(true), for(;;)) performing async I/O or LLM calls without an explicit step/retry cap can spin indefinitely.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];

      for (const file of ctx.files) {
        if (file.isTest) continue;

        if (file.ext === '.py') {
          const stripped = stripCommentsKeepLines(file.content, 'py');
          const pyWhileRe = /^\s*while\s+True\s*:/gm;
          let m: RegExpExecArray | null;
          while ((m = pyWhileRe.exec(stripped)) !== null) {
            const { body } = extractPythonIndentedBlock(stripped, m.index + m[0].length);
            if (ASYNC_IO_RE.test(body) && !BOUND_GUARD_RE.test(body)) {
              const line = offsetToLine(stripped, m.index);
              findings.push({
                ruleId: 'DAY2-COST-003',
                title: 'Unbounded Loop Invoking External or AI Services',
                category: CATEGORY,
                categoryLabel: CATEGORY_LABEL,
                severity: 'HIGH',
                file: file.relPath,
                line,
                message: 'Unbounded `while True:` loop calls external/AI operations without a max-iteration guard.',
                snippet: getLineSnippet(file.lines, line),
                remediation: 'Replace `while True:` with a bounded loop such as `for step in range(MAX_STEPS):` or enforce a retry counter.',
              });
            }
          }
          continue;
        }

        if (!['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(file.ext)) {
          continue;
        }

        const stripped = stripCommentsKeepLines(file.content, 'js');
        const loopRe = /\b(?:while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))\s*\{/g;
        let m: RegExpExecArray | null;
        while ((m = loopRe.exec(stripped)) !== null) {
          const openBraceIdx = m.index + m[0].length - 1;
          const { body } = extractBalancedBlock(stripped, openBraceIdx);
          if (ASYNC_IO_RE.test(body) && !BOUND_GUARD_RE.test(body)) {
            const line = offsetToLine(stripped, m.index);
            findings.push({
              ruleId: 'DAY2-COST-003',
              title: 'Unbounded Loop Invoking External or AI Services',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'HIGH',
              file: file.relPath,
              line,
              message: 'Unbounded loop executes async/AI calls without a maximum step or retry limit.',
              snippet: getLineSnippet(file.lines, line),
              remediation: 'Use a bounded loop (`for (let step = 0; step < MAX_STEPS; step++)`) and check `AbortSignal` before each iteration.',
            });
          }
        }
      }

      return findings;
    },
  },
];
