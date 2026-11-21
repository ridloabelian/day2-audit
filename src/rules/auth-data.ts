import {
  extractHttpRoutes,
  getLineSnippet,
  offsetToLine,
  stripCommentsKeepLines,
} from '../scanner/code-analyzer.js';
import { CATEGORIES, type Finding, type Rule, type ScanContext } from '../types.js';

const CATEGORY = 'auth-data' as const;
const CATEGORY_LABEL = CATEGORIES[CATEGORY];

const AUTH_EXEMPT_ROUTE_RE =
  /\/(?:auth|login|signin|signup|register|logout|callback|webhooks?|health|healthz|ready|live|ping)(?:\/|$)/i;

const AUTH_CHECK_RE =
  /\b(?:getServerSession|getSession|getUser|currentUser|getAuth|requireAuth|withAuth|clerkMiddleware|verifyToken|verifyJwt|jwtVerify|isAuthenticated|ensureAuthenticated|authenticate|HTTPBearer|OAuth2PasswordBearer|Depends)\b|jwt\.verify\b|headers\.get\(\s*['"]authorization['"]\s*\)|req\.headers\.authorization\b|x-api-key/i;

const CLIENT_SECRET_ENV_RE =
  /\b(?:NEXT_PUBLIC_|VITE_)[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|DATABASE_URL|PASSWORD|OPENAI_API_KEY|ANTHROPIC_API_KEY)[A-Z0-9_]*\b/g;

const SECRET_LITERAL_PATTERNS: Array<{ label: string; re: RegExp }> = [
  { label: 'OpenAI API key', re: /\bsk-proj-[A-Za-z0-9_-]{16,}\b/g },
  { label: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g },
  { label: 'Stripe live secret key', re: /\bsk_live_[A-Za-z0-9]{16,}\b/g },
  { label: 'GitHub personal access token', re: /\bghp_[A-Za-z0-9]{20,}\b/g },
  { label: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  {
    label: 'hardcoded database connection string with credentials',
    re: /\bpostgres(?:ql)?:\/\/[^/\s:'"`]+:[^/\s'"`@]+@(?!localhost\b|127\.0\.0\.1\b)[^\s'"`]+/gi,
  },
];

function maskSecrets(lineText: string): string {
  let masked = lineText
    .replace(/\b(sk-proj-|sk-ant-|sk_live_|ghp_)[A-Za-z0-9_-]+/g, '$1***REDACTED***')
    .replace(/\b(AKIA)[0-9A-Z]{16}\b/g, '$1***REDACTED***')
    .replace(
      /(postgres(?:ql)?:\/\/[^/\s:'"`]+:)[^/\s'"`@]+(@)/gi,
      '$1***REDACTED***$2',
    );
  if (masked.length > 140) masked = `${masked.slice(0, 137)}...`;
  return masked.trim();
}

function normalizeTableName(raw: string): string {
  const cleaned = raw.replace(/"/g, '').trim().toLowerCase();
  const parts = cleaned.split('.');
  return parts.length > 1 ? parts[parts.length - 1]! : cleaned;
}

function isGitignoreProtectingEnv(gitignore: string): boolean {
  const lines = gitignore
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  return lines.some((l) => /^\.?env(?:\.\*)?$|^\.env\*?$|^\/\.env/.test(l));
}

function isRealEnvFile(relPath: string): boolean {
  const base = relPath.split('/').pop()?.toLowerCase() ?? '';
  if (!base.startsWith('.env')) return false;
  return (
    base === '.env' ||
    (base.startsWith('.env.') &&
      base !== '.env.example' &&
      base !== '.env.sample' &&
      base !== '.env.template' &&
      base !== '.env.dist')
  );
}

function getWorkerEntries(ctx: ScanContext): Set<string> {
  const entries = new Set<string>();
  const wrangler = ctx.fileMap.get('wrangler.toml');
  if (wrangler) {
    const m = /^\s*main\s*=\s*['"]([^'"]+)['"]/m.exec(wrangler.content);
    if (m?.[1]) entries.add(m[1].replace(/^\.\//, ''));
  }
  if (ctx.stack.stacks.includes('cloudflare-workers')) {
    entries.add('src/index.ts');
    entries.add('src/index.js');
  }
  return entries;
}

function hasGlobalApiAuthMiddleware(ctx: ScanContext): boolean {
  const candidates = ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js'];
  for (const rel of candidates) {
    const f = ctx.fileMap.get(rel);
    if (!f) continue;
    const stripped = stripCommentsKeepLines(f.content, 'js');
    if (
      /\b(?:clerkMiddleware|withAuth|getToken|supabase\.auth\.getUser)\b/.test(stripped) ||
      (/\bauth\s*\(/.test(stripped) && /\/api/.test(stripped))
    ) {
      return true;
    }
  }
  return false;
}

export const authDataRules: Rule[] = [
  {
    id: 'DAY2-AUTH-001',
    title: 'Supabase / SQL Migration Missing Row Level Security (RLS)',
    category: CATEGORY,
    severity: 'CRITICAL',
    description:
      'SQL migrations create application tables without enabling Row Level Security (ENABLE ROW LEVEL SECURITY).',
    check(ctx: ScanContext): Finding[] {
      const hasSupabase = ctx.stack.stacks.includes('supabase');
      const sqlFiles = ctx.files.filter((f) => {
        if (f.ext !== '.sql' || f.isTest) return false;
        if (/(?:^|\/)supabase\//.test(f.relPath)) return true;
        return hasSupabase && /(?:^|\/)(?:migrations|drizzle)\//.test(f.relPath);
      });

      if (sqlFiles.length === 0) return [];

      const rlsEnabledTables = new Set<string>();
      const alterRlsRe =
        /ALTER\s+TABLE\s+(?:ONLY\s+)?([a-zA-Z0-9_."]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY\b/gi;

      for (const file of sqlFiles) {
        const stripped = stripCommentsKeepLines(file.content, 'sql');
        let m: RegExpExecArray | null;
        while ((m = alterRlsRe.exec(stripped)) !== null) {
          rlsEnabledTables.add(normalizeTableName(m[1]!));
        }
      }

      const findings: Finding[] = [];
      const createTableRe =
        /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_."]+)\s*\(/gi;

      for (const file of sqlFiles) {
        const stripped = stripCommentsKeepLines(file.content, 'sql');
        let m: RegExpExecArray | null;
        while ((m = createTableRe.exec(stripped)) !== null) {
          const rawName = m[1]!;
          const lowerRaw = rawName.replace(/"/g, '').toLowerCase();
          if (
            lowerRaw.startsWith('auth.') ||
            lowerRaw.startsWith('storage.') ||
            lowerRaw.startsWith('extensions.') ||
            lowerRaw === '_prisma_migrations' ||
            lowerRaw === 'public._prisma_migrations'
          ) {
            continue;
          }

          const norm = normalizeTableName(rawName);
          if (!rlsEnabledTables.has(norm)) {
            const line = offsetToLine(stripped, m.index);
            findings.push({
              ruleId: 'DAY2-AUTH-001',
              title: 'Supabase / SQL Migration Missing Row Level Security (RLS)',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'CRITICAL',
              file: file.relPath,
              line,
              message: `Table "${rawName.replace(/"/g, '')}" is created without ALTER TABLE ... ENABLE ROW LEVEL SECURITY.`,
              snippet: getLineSnippet(file.lines, line),
              remediation: `Enable RLS and add explicit policies:\nALTER TABLE ${rawName} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "users_own_rows" ON ${rawName} FOR ALL USING (auth.uid() = user_id);`,
            });
          }
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-AUTH-002',
    title: 'State-Mutating API Route Missing Authentication Check',
    category: CATEGORY,
    severity: 'CRITICAL',
    description:
      'POST/PUT/PATCH/DELETE API handlers mutate state without verifying a session, JWT, or API key.',
    check(ctx: ScanContext): Finding[] {
      if (hasGlobalApiAuthMiddleware(ctx)) return [];

      const workerEntries = getWorkerEntries(ctx);
      const findings: Finding[] = [];

      for (const file of ctx.files) {
        if (file.isTest) continue;
        const routes = extractHttpRoutes(file, workerEntries.has(file.relPath));
        if (routes.length === 0) continue;

        const fileStripped = stripCommentsKeepLines(
          file.content,
          file.ext === '.py' ? 'py' : 'js',
        );
        const fileHasGlobalRouterAuth =
          /(?:app|router)\.use\s*\([^)]*(?:auth|jwt|session|verify|requireUser)/i.test(
            fileStripped,
          );

        for (const route of routes) {
          const isMutating =
            route.method === 'POST' ||
            route.method === 'PUT' ||
            route.method === 'PATCH' ||
            route.method === 'DELETE' ||
            (route.method === 'ALL' && route.framework === 'nextjs-pages');
          if (!isMutating) continue;
          if (AUTH_EXEMPT_ROUTE_RE.test(route.routePath)) continue;
          if (AUTH_EXEMPT_ROUTE_RE.test(`/${file.relPath}`)) continue;

          if (fileHasGlobalRouterAuth) continue;
          if (AUTH_CHECK_RE.test(route.handlerBody)) continue;

          findings.push({
            ruleId: 'DAY2-AUTH-002',
            title: 'State-Mutating API Route Missing Authentication Check',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'CRITICAL',
            file: file.relPath,
            line: route.startLine,
            message: `${route.method} ${route.routePath} handler lacks session/token authentication checks.`,
            snippet: getLineSnippet(file.lines, route.startLine),
            remediation: `Verify the caller before mutating state:\nconst session = await getServerSession(authOptions);\nif (!session?.user) return Response.json({ error: 'Unauthorized' }, { status: 401 });`,
          });
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-AUTH-003',
    title: 'Leaked Secrets in Client Env or Git-Tracked Files',
    category: CATEGORY,
    severity: 'CRITICAL',
    description:
      'Server-side secrets are exposed via NEXT_PUBLIC_/VITE_ prefixes, committed/unignored .env files, or hardcoded API key literals.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];
      const seen = new Set<string>();
      const gitignoreOk = isGitignoreProtectingEnv(ctx.gitignoreContent);
      const trackedSet = new Set(ctx.gitTrackedEnvFiles);

      const pushUnique = (f: Finding): void => {
        const key = `${f.file}:${f.line}:${f.message}`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push(f);
        }
      };

      for (const file of ctx.files) {
        if (file.isTest) continue;

        // Vector 1: Real .env files tracked by git or unignored on disk
        if (isRealEnvFile(file.relPath)) {
          if (trackedSet.has(file.relPath) || !gitignoreOk) {
            const reason = trackedSet.has(file.relPath)
              ? `Environment file "${file.relPath}" is tracked by git.`
              : `Environment file "${file.relPath}" is present without a matching .env rule in .gitignore.`;
            pushUnique({
              ruleId: 'DAY2-AUTH-003',
              title: 'Leaked Secrets in Client Env or Git-Tracked Files',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'CRITICAL',
              file: file.relPath,
              line: 1,
              message: reason,
              remediation: `Untrack the .env file and ignore it in .gitignore:\ngit rm --cached ${file.relPath}\necho ".env\\n.env.*\\n!.env.example" >> .gitignore`,
            });
          }
        }

        const isEnvTemplate =
          /\.env\.(?:example|sample|template|dist)$/i.test(file.relPath);
        const isCodeOrEnv =
          isRealEnvFile(file.relPath) ||
          isEnvTemplate ||
          ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.yml', '.yaml', '.toml'].includes(
            file.ext,
          );
        if (!isCodeOrEnv) continue;

        const lang =
          file.ext === '.py' || file.ext === '.yml' || file.ext === '.yaml' || file.ext === '.toml' || file.relPath.includes('.env')
            ? 'py'
            : 'js';
        const stripped = stripCommentsKeepLines(file.content, lang);

        // Vector 2: Client-exposed NEXT_PUBLIC_* / VITE_* secret env vars
        const envRe = new RegExp(CLIENT_SECRET_ENV_RE.source, 'g');
        let envMatch: RegExpExecArray | null;
        while ((envMatch = envRe.exec(stripped)) !== null) {
          const line = offsetToLine(stripped, envMatch.index);
          const rawLine = file.lines[line - 1] ?? '';
          pushUnique({
            ruleId: 'DAY2-AUTH-003',
            title: 'Leaked Secrets in Client Env or Git-Tracked Files',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'CRITICAL',
            file: file.relPath,
            line,
            message: `Client-bundled env var "${envMatch[0]}" exposes a server secret to the browser bundle.`,
            snippet: maskSecrets(rawLine),
            remediation: `Remove the NEXT_PUBLIC_/VITE_ prefix from "${envMatch[0]}" and read it only inside server routes or Edge/Node workers.`,
          });
        }

        // Vector 3: Hardcoded live secret literals (skip .env.example templates)
        if (!isEnvTemplate) {
          for (const pat of SECRET_LITERAL_PATTERNS) {
            const re = new RegExp(pat.re.source, pat.re.flags);
            let m: RegExpExecArray | null;
            while ((m = re.exec(stripped)) !== null) {
              const line = offsetToLine(stripped, m.index);
              const rawLine = file.lines[line - 1] ?? '';
              pushUnique({
                ruleId: 'DAY2-AUTH-003',
                title: 'Leaked Secrets in Client Env or Git-Tracked Files',
                category: CATEGORY,
                categoryLabel: CATEGORY_LABEL,
                severity: 'CRITICAL',
                file: file.relPath,
                line,
                message: `Detected hardcoded ${pat.label} in source file.`,
                snippet: maskSecrets(rawLine),
                remediation: `Revoke and rotate this credential immediately, then load it from process.env / platform secrets instead of hardcoding it.`,
              });
            }
          }
        }
      }

      return findings;
    },
  },
];
