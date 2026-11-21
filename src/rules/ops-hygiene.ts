import { getAllPackageDeps } from '../detector/stack-detector.js';
import {
  getLineSnippet,
  offsetToLine,
  stripCommentsKeepLines,
} from '../scanner/code-analyzer.js';
import { CATEGORIES, type Finding, type Rule, type ScanContext } from '../types.js';

const CATEGORY = 'ops-hygiene' as const;
const CATEGORY_LABEL = CATEGORIES[CATEGORY];

const LOCALHOST_RE = /['"`](https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?)/gi;
const ENV_GUARD_RE =
  /\b(?:process\.env|import\.meta\.env|os\.getenv|os\.environ|NODE_ENV|ENVIRONMENT|__DEV__)\b/;

const DB_DEP_NAMES = new Set([
  'prisma',
  '@prisma/client',
  'drizzle-orm',
  '@supabase/supabase-js',
  'pg',
  'postgres',
  'mysql2',
  'mongoose',
  'typeorm',
  'sequelize',
  'knex',
]);

function findJsonKeyLine(lines: string[], key: string): number {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`"${escaped}"\\s*:`);
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]!)) return i + 1;
  }
  return 1;
}

export const opsHygieneRules: Rule[] = [
  {
    id: 'DAY2-OPS-001',
    title: 'Hardcoded Localhost URL in Runtime Code',
    category: CATEGORY,
    severity: 'HIGH',
    description:
      'Hardcoded http://localhost or 127.0.0.1 URLs without environment variable fallbacks break immediately after deployment.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];

      for (const file of ctx.files) {
        if (file.isTest) continue;
        if (
          /(?:^|\/)(?:scripts\/|Dockerfile|\.env)/.test(file.relPath) ||
          /\.config\.[jt]s$/.test(file.relPath) ||
          /(?:^|\/)(?:health|healthz)\//.test(file.relPath)
        ) {
          continue;
        }
        const lang: 'js' | 'py' | null =
          file.ext === '.py'
            ? 'py'
            : ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(file.ext)
              ? 'js'
              : null;
        if (!lang) continue;

        const stripped = stripCommentsKeepLines(file.content, lang);
        const re = new RegExp(LOCALHOST_RE.source, LOCALHOST_RE.flags);
        const seenLines = new Set<number>();

        let m: RegExpExecArray | null;
        while ((m = re.exec(stripped)) !== null) {
          const line = offsetToLine(stripped, m.index);
          if (seenLines.has(line)) continue;
          const lineText = file.lines[line - 1] ?? '';
          if (ENV_GUARD_RE.test(lineText)) continue;
          seenLines.add(line);

          findings.push({
            ruleId: 'DAY2-OPS-001',
            title: 'Hardcoded Localhost URL in Runtime Code',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'HIGH',
            file: file.relPath,
            line,
            message: `Hardcoded local URL "${m[1]}" will fail in staging and production environments.`,
            snippet: getLineSnippet(file.lines, line),
            remediation: `Read the service URL from environment configuration:\nconst baseUrl = process.env.INTERNAL_API_URL;\nif (!baseUrl) throw new Error('INTERNAL_API_URL is not configured');`,
          });
        }
      }

      return findings;
    },
  },
  {
    id: 'DAY2-OPS-002',
    title: 'Missing Lockfile or Unpinned Wildcard Dependencies',
    category: CATEGORY,
    severity: 'MEDIUM',
    description:
      'Missing lockfiles or "*" / "latest" dependencies lead to non-deterministic builds and surprise breaking upgrades.',
    check(ctx: ScanContext): Finding[] {
      const findings: Finding[] = [];

      if (ctx.packageJson) {
        const deps = getAllPackageDeps(ctx.packageJson);
        const hasAnyDeps = Object.keys(deps).length > 0;

        if (hasAnyDeps && !ctx.stack.hasLockfile) {
          findings.push({
            ruleId: 'DAY2-OPS-002',
            title: 'Missing Lockfile or Unpinned Wildcard Dependencies',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'MEDIUM',
            file: 'package.json',
            line: 1,
            message: 'No package manager lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lock) found.',
            remediation: 'Generate and commit a deterministic lockfile by running `npm install --package-lock-only` (or `pnpm install`).',
          });
        }

        for (const section of ['dependencies', 'devDependencies'] as const) {
          const rawSection = ctx.packageJson.data[section];
          if (!rawSection || typeof rawSection !== 'object' || Array.isArray(rawSection)) {
            continue;
          }
          for (const [name, version] of Object.entries(rawSection as Record<string, unknown>)) {
            if (typeof version !== 'string') continue;
            const trimmed = version.trim();
            if (trimmed === '*' || trimmed === '' || trimmed === 'latest') {
              const line = findJsonKeyLine(ctx.packageJson.raw.lines, name);
              findings.push({
                ruleId: 'DAY2-OPS-002',
                title: 'Missing Lockfile or Unpinned Wildcard Dependencies',
                category: CATEGORY,
                categoryLabel: CATEGORY_LABEL,
                severity: 'MEDIUM',
                file: 'package.json',
                line,
                message: `Dependency "${name}" uses unpinned version "${trimmed || '(empty)'}".`,
                snippet: getLineSnippet(ctx.packageJson.raw.lines, line),
                remediation: `Pin "${name}" to an explicit semver range (e.g., "${name}": "^4.86.0").`,
              });
            }
          }
        }
      }

      const reqTxt = ctx.fileMap.get('requirements.txt');
      if (reqTxt) {
        const hasPyLock = ctx.stack.lockfiles.some((l) =>
          /(?:poetry\.lock|uv\.lock|Pipfile\.lock)$/.test(l),
        );
        reqTxt.lines.forEach((rawLine, idx) => {
          const lineNo = idx + 1;
          const clean = rawLine.split('#')[0]?.trim() ?? '';
          if (!clean || clean.startsWith('-')) return;
          if (/\*/.test(clean) || (!hasPyLock && /^[A-Za-z0-9_.-]+$/.test(clean))) {
            findings.push({
              ruleId: 'DAY2-OPS-002',
              title: 'Missing Lockfile or Unpinned Wildcard Dependencies',
              category: CATEGORY,
              categoryLabel: CATEGORY_LABEL,
              severity: 'MEDIUM',
              file: reqTxt.relPath,
              line: lineNo,
              message: `Python dependency "${clean}" is unpinned without a lockfile.`,
              snippet: clean,
              remediation: `Pin the dependency version (e.g., "${clean}==0.115.0") or commit uv.lock / poetry.lock.`,
            });
          }
        });
      }

      return findings;
    },
  },
  {
    id: 'DAY2-OPS-003',
    title: 'Missing Database Migration Workflow or Backup Scripts',
    category: CATEGORY,
    severity: 'MEDIUM',
    description:
      'Database-backed projects should use versioned migrations (never destructive push in build scripts) and have documented backup automation.',
    check(ctx: ScanContext): Finding[] {
      const deps = getAllPackageDeps(ctx.packageJson);
      const hasDbDep = Object.keys(deps).some((d) => DB_DEP_NAMES.has(d));
      const pyHasDb = ctx.files.some(
        (f) =>
          (f.relPath === 'pyproject.toml' || f.relPath === 'requirements.txt') &&
          /\b(?:sqlalchemy|psycopg|alembic|prisma|supabase)\b/i.test(f.content),
      );

      const usesDatabase =
        ctx.stack.stacks.includes('prisma') ||
        ctx.stack.stacks.includes('drizzle') ||
        ctx.stack.stacks.includes('supabase') ||
        hasDbDep ||
        pyHasDb;

      if (!usesDatabase) return [];

      const findings: Finding[] = [];
      const scriptsObj =
        ctx.packageJson?.data['scripts'] &&
        typeof ctx.packageJson.data['scripts'] === 'object' &&
        !Array.isArray(ctx.packageJson.data['scripts'])
          ? (ctx.packageJson.data['scripts'] as Record<string, unknown>)
          : {};

      const anchorFile = ctx.packageJson
        ? 'package.json'
        : ctx.files.find((f) => f.relPath === 'pyproject.toml' || f.relPath === 'requirements.txt')
            ?.relPath ?? ctx.files[0]?.relPath ?? 'package.json';

      // 1. Check destructive db push in build/start/deploy/postinstall scripts
      for (const scriptName of ['build', 'start', 'deploy', 'postinstall']) {
        const cmd = scriptsObj[scriptName];
        if (typeof cmd === 'string' && /\b(?:prisma\s+db\s+push|drizzle-kit\s+push)\b/.test(cmd)) {
          const line = ctx.packageJson
            ? findJsonKeyLine(ctx.packageJson.raw.lines, scriptName)
            : 1;
          findings.push({
            ruleId: 'DAY2-OPS-003',
            title: 'Missing Database Migration Workflow or Backup Scripts',
            category: CATEGORY,
            categoryLabel: CATEGORY_LABEL,
            severity: 'MEDIUM',
            file: 'package.json',
            line,
            message: `Script "${scriptName}" runs destructive schema push ("${cmd}") instead of versioned migrations.`,
            snippet: ctx.packageJson ? getLineSnippet(ctx.packageJson.raw.lines, line) : undefined,
            remediation:
              'Replace `prisma db push` / `drizzle-kit push` in build/deploy scripts with `prisma migrate deploy` or `drizzle-kit migrate`.',
          });
        }
      }

      // 2. Check presence of migration files or migration script
      const hasMigrationFiles = ctx.allPaths.some((p) =>
        /(?:^|\/)(?:prisma\/migrations|supabase\/migrations|drizzle|migrations|alembic)\/.+/.test(
          p,
        ),
      );
      const hasMigrateScript = Object.entries(scriptsObj).some(
        ([k, v]) =>
          /migrate/i.test(k) ||
          (typeof v === 'string' && /\b(?:migrate\s+deploy|drizzle-kit\s+migrate|alembic\s+upgrade)\b/.test(v)),
      );

      if (!hasMigrationFiles && !hasMigrateScript) {
        findings.push({
          ruleId: 'DAY2-OPS-003',
          title: 'Missing Database Migration Workflow or Backup Scripts',
          category: CATEGORY,
          categoryLabel: CATEGORY_LABEL,
          severity: 'MEDIUM',
          file: anchorFile,
          line: 1,
          message: 'Database stack detected, but no versioned migration directory or migrate script was found.',
          remediation:
            'Add versioned migrations (e.g., `prisma/migrations` + `"db:migrate": "prisma migrate deploy"` in package.json).',
        });
      }

      // 3. Check presence of backup script or CI backup workflow
      const hasBackupScript = Object.keys(scriptsObj).some((k) => /backup/i.test(k));
      const hasBackupFile = ctx.allPaths.some(
        (p) =>
          /(?:^|\/)scripts\/[^/]*backup[^/]*$/.test(p) ||
          /(?:^|\/)\.github\/workflows\/[^/]*backup[^/]*\.ya?ml$/.test(p),
      );

      if (!hasBackupScript && !hasBackupFile) {
        findings.push({
          ruleId: 'DAY2-OPS-003',
          title: 'Missing Database Migration Workflow or Backup Scripts',
          category: CATEGORY,
          categoryLabel: CATEGORY_LABEL,
          severity: 'MEDIUM',
          file: anchorFile,
          line: 1,
          message: 'Database stack detected, but no backup script (`db:backup`, `scripts/*backup*`, or backup workflow) was found.',
          remediation:
            'Add a repeatable backup script (`scripts/backup-db.sh` with `pg_dump` or managed snapshot schedule) and `"db:backup"` script.',
        });
      }

      return findings;
    },
  },
];
