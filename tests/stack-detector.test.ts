import { describe, expect, it } from 'vitest';
import { buildScanContext } from '../src/scanner/engine.js';
import { withTempRepo } from './helpers.js';

describe('stack-detector', () => {
  it('detects Next.js, React, Supabase, Prisma, Docker, and AI SDKs', async () => {
    await withTempRepo(
      {
        'package.json': JSON.stringify({
          dependencies: {
            next: '^15.1.0',
            react: '^19.0.0',
            '@supabase/supabase-js': '^2.49.0',
            '@prisma/client': '^6.0.0',
            openai: '^4.80.0',
            '@anthropic-ai/sdk': '^0.39.0',
          },
        }),
        'app/layout.tsx': 'export default function L({ children }: any) { return children; }',
        'Dockerfile': 'FROM node:22-alpine\n',
        'package-lock.json': '{"lockfileVersion":3}',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        expect(ctx.stack.stacks).toEqual(
          expect.arrayContaining(['nextjs', 'react', 'supabase', 'prisma', 'docker']),
        );
        expect(ctx.stack.nextjsRouter).toBe('app');
        expect(ctx.stack.aiSdks).toEqual(expect.arrayContaining(['OpenAI', 'Anthropic']));
        expect(ctx.stack.hasLockfile).toBe(true);
      },
    );
  });

  it('detects Node APIs, Drizzle, Cloudflare Workers, and Python/FastAPI', async () => {
    await withTempRepo(
      {
        'package.json': JSON.stringify({
          dependencies: {
            express: '^4.21.0',
            'drizzle-orm': '^0.39.0',
            ai: '^4.1.0',
          },
          devDependencies: {
            wrangler: '^3.90.0',
          },
        }),
        'wrangler.toml': 'name = "edge-api"\nmain = "src/index.ts"\n',
        'pyproject.toml': '[project]\ndependencies = ["fastapi", "openai"]\n',
        'api/server.py': 'from fastapi import FastAPI\napp = FastAPI()\n',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        expect(ctx.stack.stacks).toEqual(
          expect.arrayContaining(['node-api', 'drizzle', 'cloudflare-workers', 'python-fastapi']),
        );
        expect(ctx.stack.aiSdks).toEqual(expect.arrayContaining(['OpenAI', 'Vercel AI SDK']));
      },
    );
  });
});
