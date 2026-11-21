import {
  extractHttpRoutes,
  getLineSnippet,
  offsetToLine,
  stripCommentsKeepLines,
} from '../scanner/code-analyzer.js';
import { CATEGORIES, type Finding, type Rule, type ScanContext } from '../types.js';

const CATEGORY = 'reliability' as const;
const CATEGORY_LABEL = CATEGORIES[CATEGORY];

const HEALTH_PATH_RE = /(?:^|\/)(?:api\/)?(?:health|healthz|ready|live|ping)(?:\/|$)/i;

function pickServiceAnchorFile(ctx: ScanContext): string {
  const preferred = [
    'package.json',
    'pyproject.toml',
    'requirements.txt',
    'src/index.ts',
    'src/server.ts',
    'app/layout.tsx',
    'main.py',
  ];
  for (const rel of preferred) {
    if (ctx.fileMap.has(rel)) return rel;
  }
  return ctx.files[0]?.relPath ?? 'package.json';
}

export const reliabilityRules: Rule[] = [
  {
    id: 'DAY2-REL-001',
    title: 'Missing Healthcheck Endpoint or Container Probe',
    category: CATEGORY,
    severity: 'MEDIUM',
    description:
      'Web services, APIs, and Docker containers need healthcheck endpoints and HEALTHCHECK directives for zero-downtime deploys.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];
      const stacks = new Set(ctx.stack.stacks);

      const allRoutes = ctx.files
        .filter((f) => !f.isTest)
        .flatMap((f) =>
          extractHttpRoutes(f, stacks.has('cloudflare-workers') && /^src\/index\.[jt]s$/.test(f.relPath)).map(
            (r) => ({ file: f.relPath, route: r }),
          ),
        );

      const isHttpService =
        allRoutes.length > 0 ||
        stacks.has('node-api') ||
        stacks.has('python-fastapi') ||
        stacks.has('cloudflare-workers');

      if (isHttpService) {
        const hasHealthFile = ctx.files.some((f) =>
          /(?:^|\/)(?:health|healthz|ready|live)(?:\/route)?\.[jt]sx?$|_(?:health|healthz)\.py$/.test(
            f.relPath,
          ),
        );
        const hasHealthRoute = allRoutes.some((r) => HEALTH_PATH_RE.test(r.route.routePath));

        if (!hasHealthFile && !hasHealthRoute) {
          const anchor = pickServiceAnchorFile(ctx);
          findings.push({
            ruleId: 'DAY2-REL-001',
            title: 'Missing Healthcheck Endpoint or Container Probe',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'MEDIUM',
            file: anchor,
            line: 1,
            message: 'No HTTP healthcheck route (/health, /healthz, or /api/health) was detected.',
            remediation: `Expose a lightweight healthcheck endpoint:\nexport async function GET() {\n  return Response.json({ ok: true, timestamp: Date.now() });\n}`,
          });
        }
      }

      const dockerfiles = ctx.files.filter((f) =>
        /(?:^|\/)Dockerfile(?:\.[^/]+)?$/.test(f.relPath),
      );
      for (const df of dockerfiles) {
        if (!/^\s*HEALTHCHECK\b/m.test(df.content)) {
          findings.push({
            ruleId: 'DAY2-REL-001',
            title: 'Missing Healthcheck Endpoint or Container Probe',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'MEDIUM',
            file: df.relPath,
            line: 1,
            message: `${df.relPath} does not define a Docker HEALTHCHECK instruction.`,
            snippet: getLineSnippet(df.lines, 1),
            remediation:
              'Add a container health probe in Dockerfile:\nHEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://127.0.0.1:3000/api/health || exit 1',
          });
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-REL-002',
    title: 'Missing Error Boundary or Global Error Handler',
    category: CATEGORY,
    severity: 'MEDIUM',
    description:
      'Applications lack framework error boundaries (Next.js error.tsx, React ErrorBoundary, or global API error middleware).',
    check(ctx: ScanContext): Finding[] {
      const stacks = new Set(ctx.stack.stacks);

      // Next.js App Router
      if (
        stacks.has('nextjs') &&
        (ctx.stack.nextjsRouter === 'app' || ctx.stack.nextjsRouter === 'hybrid')
      ) {
        const hasNextErrorFile = ctx.files.some((f) =>
          /(?:^|\/)app\/(?:global-)?error\.[jt]sx?$/.test(f.relPath),
        );
        if (!hasNextErrorFile) {
          const layout =
            ctx.files.find((f) => /(?:^|\/)app\/layout\.[jt]sx?$/.test(f.relPath)) ??
            ctx.files.find((f) => /(?:^|\/)app\/page\.[jt]sx?$/.test(f.relPath));
          return [
            {
              ruleId: 'DAY2-REL-002',
              title: 'Missing Error Boundary or Global Error Handler',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'MEDIUM',
              file: layout?.relPath ?? 'app/layout.tsx',
              line: 1,
              message: 'Next.js App Router project is missing app/error.tsx or app/global-error.tsx.',
              remediation: `Add an App Router error boundary in app/error.tsx:\n'use client';\nexport default function Error({ reset }: { error: Error; reset: () => void }) {\n  return <button onClick={() => reset()}>Try again</button>;\n}`,
            },
          ];
        }
        return [];
      }

      // React SPA
      if (stacks.has('react') && !stacks.has('nextjs')) {
        const hasBoundary = ctx.files.some(
          (f) =>
            !f.isTest &&
            ['.ts', '.tsx', '.js', '.jsx'].includes(f.ext) &&
            /\b(?:ErrorBoundary|errorElement|componentDidCatch|getDerivedStateFromError)\b/.test(
              stripCommentsKeepLines(f.content, 'js'),
            ),
        );
        if (!hasBoundary) {
          const anchor =
            ctx.files.find((f) => /\.[jt]sx$/.test(f.relPath) && !f.isTest)?.relPath ??
            'package.json';
          return [
            {
              ruleId: 'DAY2-REL-002',
              title: 'Missing Error Boundary or Global Error Handler',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'MEDIUM',
              file: anchor,
              line: 1,
              message: 'React application does not wrap routes or components in an ErrorBoundary.',
              remediation:
                'Wrap your root component tree with react-error-boundary (<ErrorBoundary fallback={<Fallback />}>) so UI crashes degrade gracefully.',
            },
          ];
        }
        return [];
      }

      // Node API / FastAPI
      if (stacks.has('node-api') || stacks.has('python-fastapi')) {
        const hasGlobalErrorHandler = ctx.files.some((f) => {
          if (f.isTest) return false;
          if (f.ext === '.py') {
            return /@(?:app|router)\.exception_handler\b|add_exception_handler\b/.test(
              stripCommentsKeepLines(f.content, 'py'),
            );
          }
          if (['.ts', '.js', '.mjs', '.cjs'].includes(f.ext)) {
            const stripped = stripCommentsKeepLines(f.content, 'js');
            return (
              /\(\s*err\w*\s*(?::[^)]*)?,\s*_?req\w*\s*(?::[^)]*)?,\s*res\w*\s*(?::[^)]*)?,\s*_?next\w*\s*(?::[^)]*)?\)/.test(
                stripped,
              ) ||
              /\.setErrorHandler\s*\(/.test(stripped) ||
              /\.onError\s*\(/.test(stripped)
            );
          }
          return false;
        });

        if (!hasGlobalErrorHandler) {
          return [
            {
              ruleId: 'DAY2-REL-002',
              title: 'Missing Error Boundary or Global Error Handler',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'MEDIUM',
              file: pickServiceAnchorFile(ctx),
              line: 1,
              message: 'API service lacks a global error handler middleware.',
              remediation:
                'Register global error middleware (e.g., Express `app.use((err, req, res, next) => ...)`, Hono `app.onError(...)`, or FastAPI `@app.exception_handler`).',
            },
          ];
        }
      }

      return [];
    },
  },
  {
    id: 'DAY2-REL-003',
    title: 'Swallowed Errors or Unhandled Promise Rejections',
    category: CATEGORY,
    severity: 'HIGH',
    description:
      'Empty catch/except blocks hide production failures, and long-lived Node servers without unhandledRejection listeners crash silently.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];

      let hasUnhandledRejectionGuard = false;
      const listenSites: Array<{ file: string; line: number; snippet?: string }> = [];

      for (const file of ctx.files) {
        if (file.isTest) continue;

        if (file.ext === '.py') {
          const stripped = stripCommentsKeepLines(file.content, 'py');
          const emptyExceptRe = /^\s*except(?:\s+[^:\n]+)?:\s*\n\s*pass\b/gm;
          let m: RegExpExecArray | null;
          while ((m = emptyExceptRe.exec(stripped)) !== null) {
            const line = offsetToLine(stripped, m.index);
            findings.push({
              ruleId: 'DAY2-REL-003',
              title: 'Swallowed Errors or Unhandled Promise Rejections',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'HIGH',
              file: file.relPath,
              line,
              message: 'Empty `except: pass` block silently swallows runtime exceptions.',
              snippet: getLineSnippet(file.lines, line),
              remediation: 'Log or re-raise the exception with structured context instead of silently ignoring it.',
            });
          }
          continue;
        }

        if (!['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(file.ext)) {
          continue;
        }

        const stripped = stripCommentsKeepLines(file.content, 'js');
        if (/process\.on\s*\(\s*['"]unhandledRejection['"]/.test(stripped)) {
          hasUnhandledRejectionGuard = true;
        }

        const emptyCatchRe = /\bcatch\s*(?:\(\s*[^)]*\s*\))?\s*\{\s*\}/g;
        let m: RegExpExecArray | null;
        while ((m = emptyCatchRe.exec(stripped)) !== null) {
          const line = offsetToLine(stripped, m.index);
          findings.push({
            ruleId: 'DAY2-REL-003',
            title: 'Swallowed Errors or Unhandled Promise Rejections',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'HIGH',
            file: file.relPath,
            line,
            message: 'Empty catch block silently swallows errors.',
            snippet: getLineSnippet(file.lines, line),
            remediation:
              'Log the error with structured telemetry or propagate it (`console.error(err); throw err;`).',
          });
        }

        if (ctx.stack.stacks.includes('node-api')) {
          const listenMatch = /\b(?:app|server|fastify)\.listen\s*\(/.exec(stripped);
          if (listenMatch) {
            const line = offsetToLine(stripped, listenMatch.index);
            listenSites.push({
              file: file.relPath,
              line,
              snippet: getLineSnippet(file.lines, line),
            });
          }
        }
      }

      if (listenSites.length > 0 && !hasUnhandledRejectionGuard) {
        const site = listenSites[0]!;
        findings.push({
          ruleId: 'DAY2-REL-003',
          title: 'Swallowed Errors or Unhandled Promise Rejections',
          category: CATEGORY,
          categoryLabel: CATEGORY_LABEL,
          severity: 'HIGH',
          file: site.file,
          line: site.line,
          message:
            'Node HTTP server runs `.listen()` without registering a `process.on("unhandledRejection")` handler.',
          snippet: site.snippet,
          remediation:
            "Register top-level process handlers:\nprocess.on('unhandledRejection', (err) => { console.error('Unhandled rejection', err); process.exit(1); });",
        });
      }

      return findings;
    },
  },
];
