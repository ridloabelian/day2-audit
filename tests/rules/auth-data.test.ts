import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { authDataRules } from '../../src/rules/auth-data.js';
import { buildScanContext } from '../../src/scanner/engine.js';
import { withTempRepo } from '../helpers.js';

function runRule(id: string, ctx: Awaited<ReturnType<typeof buildScanContext>>) {
  const rule = authDataRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Missing rule ${id}`);
  return rule.check(ctx);
}

describe('Auth & Data Exposure rules', () => {
  it('DAY2-AUTH-001 flags Supabase tables missing ENABLE ROW LEVEL SECURITY and ignores hardened ones', async () => {
    await withTempRepo(
      {
        'supabase/migrations/001_tables.sql': [
          'CREATE TABLE public.items (id uuid primary key);',
          'CREATE TABLE public.orders (id uuid primary key);',
          '-- CREATE TABLE public.commented_out (id uuid);',
        ].join('\n'),
        'supabase/migrations/002_rls.sql': 'ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;\n',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-AUTH-001', ctx);
        expect(findings).toHaveLength(1);
        expect(findings[0]?.line).toBe(2);
        expect(findings[0]?.message).toContain('public.orders');
      },
    );
  });

  it('DAY2-AUTH-002 flags mutating routes without auth and passes authenticated/exempt routes', async () => {
    await withTempRepo(
      {
        'app/api/posts/route.ts': [
          'export async function POST(req: Request) {',
          '  const body = await req.json();',
          '  return Response.json(body);',
          '}',
        ].join('\n'),
        'app/api/secure/route.ts': [
          'export async function POST(req: Request) {',
          '  const session = await getServerSession();',
          '  if (!session) return new Response("Unauthorized", { status: 401 });',
          '  return Response.json({ ok: true });',
          '}',
        ].join('\n'),
        'app/api/auth/login/route.ts':
          'export async function POST(req: Request) { return Response.json({ ok: true }); }\n',
        'api.py': [
          'from fastapi import FastAPI',
          'app = FastAPI()',
          '@app.delete("/items/{item_id}")',
          'async def delete_item(item_id: str):',
          '    return {"deleted": item_id}',
        ].join('\n'),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-AUTH-002', ctx);
        expect(findings).toHaveLength(2);
        expect(findings.map((f) => f.file).sort()).toEqual([
          'api.py',
          'app/api/posts/route.ts',
        ]);
      },
    );
  });

  it('DAY2-AUTH-003 detects NEXT_PUBLIC_ secrets, hardcoded keys, and git-tracked .env files', async () => {
    const fakeOpenAiKey = 'sk-proj-' + 'a1B2c3D4e5F6g7H8i9J0';
    await withTempRepo(
      {
        '.gitignore': 'node_modules/\n',
        '.env': 'DATABASE_URL=postgres://user:pass@db.example.com:5432/app\n',
        '.env.example': 'NEXT_PUBLIC_APP_URL=https://example.com\n',
        'src/client.ts': [
          'const pub = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;',
          `const key = "${fakeOpenAiKey}";`,
          `// ${fakeOpenAiKey} in a comment should be ignored`,
        ].join('\n'),
      },
      async (dir) => {
        execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });
        execFileSync('git', ['add', '-f', '.env'], { cwd: dir, stdio: 'ignore' });

        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-AUTH-003', ctx);
        expect(findings.length).toBeGreaterThanOrEqual(3);
        expect(findings.some((f) => f.file === '.env')).toBe(true);
        expect(findings.some((f) => f.file === 'src/client.ts' && f.line === 1)).toBe(true);
        expect(findings.some((f) => f.file === 'src/client.ts' && f.line === 2)).toBe(true);
        expect(findings.some((f) => f.file === 'src/client.ts' && f.line === 3)).toBe(false);
        expect(findings.every((f) => !(f.snippet ?? '').includes(fakeOpenAiKey))).toBe(true);
      },
    );
  });
});
