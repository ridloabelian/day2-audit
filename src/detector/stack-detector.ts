import path from 'node:path';
import type { DetectedStackId, PackageJsonContext, ScannedFile, StackProfile } from '../types.js';

const LOCKFILE_NAMES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
  'poetry.lock',
  'uv.lock',
  'Pipfile.lock',
]);

export function parsePackageJson(files: ScannedFile[]): PackageJsonContext | undefined {
  const pkgFile = files.find((f) => f.relPath === 'package.json');
  if (!pkgFile) return undefined;
  try {
    const parsed = JSON.parse(pkgFile.content) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { raw: pkgFile, data: parsed as Record<string, unknown> };
    }
  } catch {
    return undefined;
  }
  return undefined;
}

export function getAllPackageDeps(pkg?: PackageJsonContext): Record<string, string> {
  if (!pkg) return {};
  const deps: Record<string, string> = {};
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
    const section = pkg.data[field];
    if (section && typeof section === 'object' && !Array.isArray(section)) {
      for (const [name, version] of Object.entries(section as Record<string, unknown>)) {
        if (typeof version === 'string') {
          deps[name] = version;
        }
      }
    }
  }
  return deps;
}

export function detectStack(
  files: ScannedFile[],
  allPaths: string[],
  pkg?: PackageJsonContext,
): StackProfile {
  const deps = getAllPackageDeps(pkg);
  const depNames = new Set(Object.keys(deps));
  const stacks = new Set<DetectedStackId>();
  const labels: string[] = [];
  const aiSdks = new Set<string>();

  const lockfiles = allPaths.filter((p) => LOCKFILE_NAMES.has(path.basename(p)));
  const hasLockfile = lockfiles.length > 0;

  const hasPathMatch = (re: RegExp): boolean => allPaths.some((p) => re.test(p));
  const hasCodeMatch = (exts: string[], re: RegExp): boolean =>
    files.some((f) => !f.isTest && exts.includes(f.ext) && re.test(f.content));

  const jsExts = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

  // Next.js & Router detection
  const hasAppRouter = hasPathMatch(/(?:^|\/)app\/(?:layout|page|route)\.[jt]sx?$/);
  const hasPagesRouter = hasPathMatch(/(?:^|\/)pages\/.+?\.[jt]sx?$/);
  let nextjsRouter: StackProfile['nextjsRouter'];
  if (hasAppRouter && hasPagesRouter) nextjsRouter = 'hybrid';
  else if (hasAppRouter) nextjsRouter = 'app';
  else if (hasPagesRouter) nextjsRouter = 'pages';

  if (depNames.has('next') || hasPathMatch(/^next\.config\./)) {
    stacks.add('nextjs');
    const routerTag =
      nextjsRouter === 'app'
        ? ' (App Router)'
        : nextjsRouter === 'pages'
          ? ' (Pages Router)'
          : nextjsRouter === 'hybrid'
            ? ' (App + Pages)'
            : '';
    labels.push(`Next.js${routerTag}`);
  }

  // React
  if (depNames.has('react') || depNames.has('react-dom') || hasPathMatch(/\.[jt]sx$/)) {
    stacks.add('react');
    labels.push('React');
  }

  // Node APIs
  const nodeApiFrameworks: string[] = [];
  if (depNames.has('express') || hasCodeMatch(jsExts, /from\s+['"]express['"]|require\(['"]express['"]\)/)) {
    nodeApiFrameworks.push('Express');
  }
  if (depNames.has('fastify') || hasCodeMatch(jsExts, /from\s+['"]fastify['"]|require\(['"]fastify['"]\)/)) {
    nodeApiFrameworks.push('Fastify');
  }
  if (depNames.has('hono') || hasCodeMatch(jsExts, /from\s+['"]hono(?:\/|['"])/)) {
    nodeApiFrameworks.push('Hono');
  }
  if (depNames.has('@nestjs/core')) nodeApiFrameworks.push('NestJS');
  if (depNames.has('koa')) nodeApiFrameworks.push('Koa');
  if (depNames.has('elysia')) nodeApiFrameworks.push('Elysia');

  if (nodeApiFrameworks.length > 0) {
    stacks.add('node-api');
    labels.push(`Node API (${nodeApiFrameworks.join('/')})`);
  }

  // Supabase
  if (
    depNames.has('@supabase/supabase-js') ||
    depNames.has('@supabase/ssr') ||
    hasPathMatch(/(?:^|\/)supabase\/(?:config\.toml|migrations\/.+\.sql)$/)
  ) {
    stacks.add('supabase');
    labels.push('Supabase');
  }

  // Prisma
  if (
    depNames.has('prisma') ||
    depNames.has('@prisma/client') ||
    hasPathMatch(/(?:^|\/)prisma\/schema\.prisma$/)
  ) {
    stacks.add('prisma');
    labels.push('Prisma');
  }

  // Drizzle
  if (
    depNames.has('drizzle-orm') ||
    depNames.has('drizzle-kit') ||
    hasPathMatch(/(?:^|\/)drizzle\.config\.[jt]s$/)
  ) {
    stacks.add('drizzle');
    labels.push('Drizzle');
  }

  // Cloudflare Workers
  if (
    hasPathMatch(/^wrangler\.(?:toml|json|jsonc)$/) ||
    depNames.has('wrangler') ||
    depNames.has('@cloudflare/workers-types')
  ) {
    stacks.add('cloudflare-workers');
    labels.push('Cloudflare Workers');
  }

  // Docker
  if (
    hasPathMatch(/(?:^|\/)Dockerfile(?:\.[^/]+)?$/) ||
    hasPathMatch(/(?:^|\/)(?:docker-)?compose\.ya?ml$/)
  ) {
    stacks.add('docker');
    labels.push('Docker');
  }

  // Python / FastAPI
  const pyFiles = files.filter((f) => f.ext === '.py' && !f.isTest);
  const pyDepsFiles = files.filter(
    (f) => f.relPath === 'pyproject.toml' || f.relPath === 'requirements.txt' || f.relPath === 'Pipfile',
  );
  const hasFastapiInDeps = pyDepsFiles.some((f) => /\bfastapi\b/i.test(f.content));
  const hasFastapiInCode = pyFiles.some((f) => /\bfrom\s+fastapi\b|\bFastAPI\s*\(/.test(f.content));
  if (hasFastapiInDeps || hasFastapiInCode) {
    stacks.add('python-fastapi');
    labels.push('Python / FastAPI');
  } else if (pyFiles.length > 0 || pyDepsFiles.length > 0) {
    labels.push('Python');
  }

  // AI SDKs
  const pyAndDepsText = [...pyFiles, ...pyDepsFiles].map((f) => f.content).join('\n');
  if (
    depNames.has('openai') ||
    hasCodeMatch(jsExts, /from\s+['"]openai['"]|new\s+OpenAI\s*\(/) ||
    /\bopenai\b/i.test(pyAndDepsText)
  ) {
    aiSdks.add('OpenAI');
  }
  if (
    depNames.has('@anthropic-ai/sdk') ||
    hasCodeMatch(jsExts, /from\s+['"]@anthropic-ai\/sdk['"]|new\s+Anthropic\s*\(/) ||
    /\banthropic\b/i.test(pyAndDepsText)
  ) {
    aiSdks.add('Anthropic');
  }
  if (
    depNames.has('ai') ||
    [...depNames].some((d) => d.startsWith('@ai-sdk/')) ||
    hasCodeMatch(jsExts, /from\s+['"]ai['"]/)
  ) {
    aiSdks.add('Vercel AI SDK');
  }
  if (depNames.has('@google/generative-ai') || depNames.has('@google/genai')) {
    aiSdks.add('Google Gemini SDK');
  }
  if (depNames.has('langchain') || depNames.has('@langchain/core')) {
    aiSdks.add('LangChain');
  }

  return {
    stacks: Array.from(stacks),
    labels,
    aiSdks: Array.from(aiSdks),
    nextjsRouter,
    hasLockfile,
    lockfiles,
  };
}
