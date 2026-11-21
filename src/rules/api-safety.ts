import {
  extractHttpRoutes,
  getLineSnippet,
  offsetToLine,
  stripCommentsKeepLines,
} from '../scanner/code-analyzer.js';
import { CATEGORIES, type Finding, type Rule, type ScanContext } from '../types.js';

const CATEGORY = 'api-safety' as const;
const CATEGORY_LABEL = CATEGORIES[CATEGORY];

const WEBHOOK_SIG_RE =
  /\b(?:constructEvent|constructEventAsync|verifyWebhook|verifySignature|timingSafeEqual|createHmac|compare_digest|verify_signature|svix)\b|wh\.verify\s*\(|new\s+Webhook\s*\(/;

const CORS_PATTERNS: Array<{ re: RegExp; detail: string }> = [
  {
    re: /['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]/g,
    detail: 'Access-Control-Allow-Origin set to "*"',
  },
  {
    re: /(?:^|[=(,\s])cors\s*\(\s*\)(?=\s*[),;\n]|$)/gm,
    detail: 'cors() called without an explicit origin allowlist',
  },
  {
    re: /\borigin\s*:\s*['"]\*['"]/g,
    detail: 'CORS origin configured as wildcard "*"',
  },
  {
    re: /\ballow_origins\s*=\s*\[\s*['"]\*['"]\s*\]/g,
    detail: 'FastAPI CORSMiddleware allow_origins set to ["*"]',
  },
];

const RAW_SQL_PATTERNS: Array<{ re: RegExp; detail: string; lang: 'js' | 'py' }> = [
  {
    lang: 'js',
    re: /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(/g,
    detail: 'Prisma $queryRawUnsafe / $executeRawUnsafe used instead of parameterized $queryRaw',
  },
  {
    lang: 'js',
    re: /\b(?:query|execute|raw)\s*\(\s*`[^`]{0,220}\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]{0,220}\$\{/gi,
    detail: 'SQL query string built with template literal interpolation (${...})',
  },
  {
    lang: 'py',
    re: /\.execute\s*\(\s*(?:text\s*\(\s*)?f['"](?:SELECT|INSERT|UPDATE|DELETE)\b/gi,
    detail: 'Python SQL execution built using an f-string',
  },
];

export const apiSafetyRules: Rule[] = [
  {
    id: 'DAY2-API-001',
    title: 'Webhook Endpoint Missing Signature Verification',
    category: CATEGORY,
    severity: 'CRITICAL',
    description:
      'Webhook handlers process incoming events without cryptographic signature verification (Stripe constructEvent, Svix, or HMAC).',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];

      for (const file of ctx.files) {
        if (file.isTest) continue;
        const routes = extractHttpRoutes(file, false);
        if (routes.length === 0) continue;

        const lang = file.ext === '.py' ? 'py' : 'js';
        const stripped = stripCommentsKeepLines(file.content, lang);
        const fileIsWebhook = /webhooks?/i.test(file.relPath);
        const hasSignatureCheck = WEBHOOK_SIG_RE.test(stripped);

        for (const route of routes) {
          const isWebhookRoute = fileIsWebhook || /webhooks?/i.test(route.routePath);
          if (!isWebhookRoute) continue;
          if (hasSignatureCheck) continue;

          findings.push({
            ruleId: 'DAY2-API-001',
            title: 'Webhook Endpoint Missing Signature Verification',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'CRITICAL',
            file: file.relPath,
            line: route.startLine,
            message: `Webhook handler (${route.method} ${route.routePath}) does not verify request signatures.`,
            snippet: getLineSnippet(file.lines, route.startLine),
            remediation: `Verify the raw request body against the provider signature:\nconst sig = req.headers.get('stripe-signature')!;\nconst event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!);`,
          });
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-API-002',
    title: 'Permissive Wildcard CORS Configuration',
    category: CATEGORY,
    severity: 'MEDIUM',
    description:
      'Wildcard CORS ("*") allows arbitrary third-party origins to read responses or invoke APIs from user browsers.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];
      const seen = new Set<string>();

      for (const file of ctx.files) {
        if (file.isTest) continue;
        if (!['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py'].includes(file.ext)) {
          continue;
        }

        const lang = file.ext === '.py' ? 'py' : 'js';
        const stripped = stripCommentsKeepLines(file.content, lang);

        for (const pat of CORS_PATTERNS) {
          const re = new RegExp(pat.re.source, pat.re.flags);
          let m: RegExpExecArray | null;
          while ((m = re.exec(stripped)) !== null) {
            const line = offsetToLine(stripped, m.index);
            const key = `${file.relPath}:${line}`;
            if (seen.has(key)) continue;
            seen.add(key);

            findings.push({
              ruleId: 'DAY2-API-002',
              title: 'Permissive Wildcard CORS Configuration',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'MEDIUM',
              file: file.relPath,
              line,
              message: `${pat.detail}.`,
              snippet: getLineSnippet(file.lines, line),
              remediation: `Restrict CORS to explicit trusted origins via environment config:\nconst allowedOrigin = process.env.ALLOWED_ORIGIN ?? 'https://app.example.com';`,
            });
          }
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-API-003',
    title: 'Unsafe Raw SQL String Interpolation',
    category: CATEGORY,
    severity: 'HIGH',
    description:
      'Raw SQL helpers or template-interpolated queries risk SQL injection vulnerabilities in production.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];
      const seen = new Set<string>();

      for (const file of ctx.files) {
        if (file.isTest) continue;
        const lang: 'js' | 'py' | null =
          file.ext === '.py'
            ? 'py'
            : ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(file.ext)
              ? 'js'
              : null;
        if (!lang) continue;

        const stripped = stripCommentsKeepLines(file.content, lang);
        for (const pat of RAW_SQL_PATTERNS) {
          if (pat.lang !== lang) continue;
          const re = new RegExp(pat.re.source, pat.re.flags);
          let m: RegExpExecArray | null;
          while ((m = re.exec(stripped)) !== null) {
            const line = offsetToLine(stripped, m.index);
            const key = `${file.relPath}:${line}`;
            if (seen.has(key)) continue;
            seen.add(key);

            findings.push({
              ruleId: 'DAY2-API-003',
              title: 'Unsafe Raw SQL String Interpolation',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'HIGH',
              file: file.relPath,
              line,
              message: `${pat.detail}.`,
              snippet: getLineSnippet(file.lines, line),
              remediation: 'Use parameterized queries (e.g., Prisma tagged template `prisma.$queryRaw` or `$1` bound parameters) instead of string interpolation.',
            });
          }
        }
      }

      return findings;
    },
  },
];
