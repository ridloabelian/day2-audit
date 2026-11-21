import { describe, expect, it } from 'vitest';
import { reliabilityRules } from '../../src/rules/reliability.js';
import { buildScanContext } from '../../src/scanner/engine.js';
import { withTempRepo } from '../helpers.js';

function runRule(id: string, ctx: Awaited<ReturnType<typeof buildScanContext>>) {
  const rule = reliabilityRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Missing rule ${id}`);
  return rule.check(ctx);
}

describe('Reliability & Resilience rules', () => {
  it('DAY2-REL-001 flags missing HTTP health endpoint and missing Dockerfile HEALTHCHECK', async () => {
    await withTempRepo(
      {
        'package.json': JSON.stringify({ dependencies: { express: '^4.21.0' } }),
        'src/index.ts': 'import express from "express";\nconst app = express();\napp.get("/users", () => {});\n',
        'Dockerfile': 'FROM node:22-alpine\nCMD ["node", "dist/index.js"]\n',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-REL-001', ctx);
        expect(findings).toHaveLength(2);
        expect(findings.some((f) => f.file === 'Dockerfile')).toBe(true);
      },
    );
  });

  it('DAY2-REL-002 flags Next.js App Router without error.tsx and Express without error middleware', async () => {
    await withTempRepo(
      {
        'package.json': JSON.stringify({ dependencies: { next: '^15.1.0', react: '^19.0.0' } }),
        'app/layout.tsx': 'export default function L({ children }: any) { return children; }\n',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-REL-002', ctx);
        expect(findings).toHaveLength(1);
        expect(findings[0]?.message).toContain('error.tsx');
      },
    );

    await withTempRepo(
      {
        'package.json': JSON.stringify({ dependencies: { express: '^4.21.0' } }),
        'src/app.ts': 'import express from "express";\nconst app = express();\n',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-REL-002', ctx);
        expect(findings).toHaveLength(1);
      },
    );
  });

  it('DAY2-REL-003 flags empty catch blocks and Node .listen() without unhandledRejection', async () => {
    await withTempRepo(
      {
        'package.json': JSON.stringify({ dependencies: { express: '^4.21.0' } }),
        'src/server.ts': [
          'import express from "express";',
          'const app = express();',
          'try {',
          '  JSON.parse("{}");',
          '} catch (e) {}',
          'app.listen(3000);',
        ].join('\n'),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-REL-003', ctx);
        expect(findings).toHaveLength(2);
        expect(findings[0]?.line).toBe(5);
        expect(findings[1]?.line).toBe(6);
      },
    );
  });
});
