import { describe, expect, it } from 'vitest';
import { opsHygieneRules } from '../../src/rules/ops-hygiene.js';
import { buildScanContext } from '../../src/scanner/engine.js';
import { withTempRepo } from '../helpers.js';

function runRule(id: string, ctx: Awaited<ReturnType<typeof buildScanContext>>) {
  const rule = opsHygieneRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Missing rule ${id}`);
  return rule.check(ctx);
}

describe('Ops & Dependency Hygiene rules', () => {
  it('DAY2-OPS-001 flags hardcoded localhost URLs while ignoring env fallbacks and comments', async () => {
    await withTempRepo(
      {
        'src/client.ts': [
          '// http://localhost:3000 in comment',
          'const safe = process.env.API_URL ?? "http://localhost:3000";',
          'const bad = "http://127.0.0.1:8080/api";',
        ].join('\n'),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-OPS-001', ctx);
        expect(findings).toHaveLength(1);
        expect(findings[0]?.line).toBe(3);
      },
    );
  });

  it('DAY2-OPS-002 flags missing lockfile and wildcard/latest dependencies', async () => {
    await withTempRepo(
      {
        'package.json': JSON.stringify(
          {
            dependencies: {
              openai: '*',
              zod: 'latest',
              express: '^4.21.0',
            },
          },
          null,
          2,
        ),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-OPS-002', ctx);
        expect(findings).toHaveLength(3);
      },
    );
  });

  it('DAY2-OPS-003 flags db push in build script and missing migration/backup setup', async () => {
    await withTempRepo(
      {
        'package.json': JSON.stringify(
          {
            scripts: {
              build: 'prisma db push && next build',
            },
            dependencies: {
              '@prisma/client': '^6.2.0',
            },
          },
          null,
          2,
        ),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-OPS-003', ctx);
        expect(findings).toHaveLength(3);
      },
    );
  });
});
