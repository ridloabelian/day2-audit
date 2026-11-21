import { describe, expect, it } from 'vitest';
import { apiSafetyRules } from '../../src/rules/api-safety.js';
import { buildScanContext } from '../../src/scanner/engine.js';
import { withTempRepo } from '../helpers.js';

function runRule(id: string, ctx: Awaited<ReturnType<typeof buildScanContext>>) {
  const rule = apiSafetyRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Missing rule ${id}`);
  return rule.check(ctx);
}

describe('API & Webhook Safety rules', () => {
  it('DAY2-API-001 flags unverified webhooks and passes Stripe/HMAC verified ones', async () => {
    await withTempRepo(
      {
        'app/api/webhooks/clerk/route.ts':
          'export async function POST(req: Request) { return Response.json(await req.json()); }\n',
        'app/api/webhooks/stripe/route.ts': [
          'export async function POST(req: Request) {',
          '  const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);',
          '  return Response.json({ id: event.type });',
          '}',
        ].join('\n'),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-API-001', ctx);
        expect(findings).toHaveLength(1);
        expect(findings[0]?.file).toBe('app/api/webhooks/clerk/route.ts');
      },
    );
  });

  it('DAY2-API-002 flags wildcard CORS in JS and Python FastAPI', async () => {
    await withTempRepo(
      {
        'src/server.ts': [
          'import cors from "cors";',
          'app.use(cors());',
          'const safe = cors({ origin: process.env.ALLOWED_ORIGIN });',
        ].join('\n'),
        'main.py': [
          'from fastapi.middleware.cors import CORSMiddleware',
          'app.add_middleware(CORSMiddleware, allow_origins=["*"])',
        ].join('\n'),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-API-002', ctx);
        expect(findings).toHaveLength(2);
        expect(findings.map((f) => `${f.file}:${f.line}`).sort()).toEqual([
          'main.py:2',
          'src/server.ts:2',
        ]);
      },
    );
  });

  it('DAY2-API-003 flags raw SQL interpolation and ignores parameterized queries', async () => {
    await withTempRepo(
      {
        'src/db.ts': [
          'export async function bad(prisma: any, email: string) {',
          '  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = ${email}`);',
          '}',
          'export async function good(prisma: any, email: string) {',
          '  return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;',
          '}',
        ].join('\n'),
        'db.py': 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-API-003', ctx);
        expect(findings).toHaveLength(2);
        expect(findings.map((f) => `${f.file}:${f.line}`).sort()).toEqual([
          'db.py:1',
          'src/db.ts:2',
        ]);
      },
    );
  });
});
