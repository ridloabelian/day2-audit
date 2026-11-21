import { describe, expect, it } from 'vitest';
import { costAbuseRules } from '../../src/rules/cost-abuse.js';
import { buildScanContext } from '../../src/scanner/engine.js';
import { withTempRepo } from '../helpers.js';

function runRule(id: string, ctx: Awaited<ReturnType<typeof buildScanContext>>) {
  const rule = costAbuseRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Missing rule ${id}`);
  return rule.check(ctx);
}

describe('Cost & Abuse Protection rules', () => {
  it('DAY2-COST-001 flags LLM SDK calls without max_tokens or timeout and passes bounded ones', async () => {
    await withTempRepo(
      {
        'src/unsafe-ai.ts': [
          'export async function run(openai: any) {',
          '  return openai.chat.completions.create({',
          '    model: "gpt-4o",',
          '    messages: [{ role: "user", content: "hi" }],',
          '  });',
          '}',
        ].join('\n'),
        'src/safe-ai.ts': [
          'export async function runSafe(anthropic: any) {',
          '  return anthropic.messages.create({',
          '    model: "claude-sonnet-4-5",',
          '    max_tokens: 1024,',
          '    messages: [{ role: "user", content: "hi" }],',
          '  }, { timeout: 15_000 });',
          '}',
        ].join('\n'),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-COST-001', ctx);
        expect(findings).toHaveLength(1);
        expect(findings[0]?.file).toBe('src/unsafe-ai.ts');
        expect(findings[0]?.line).toBe(2);
        expect(findings[0]?.message).toContain('max_tokens');
        expect(findings[0]?.message).toContain('timeout');
      },
    );
  });

  it('DAY2-COST-002 flags public routes missing rate limiting and passes global/local limiters', async () => {
    await withTempRepo(
      {
        'app/api/open/route.ts':
          'export async function POST() { return Response.json({ ok: true }); }\n',
        'app/api/limited/route.ts': [
          'import { Ratelimit } from "@upstash/ratelimit";',
          'export async function POST() {',
          '  const { success } = await ratelimit.limit("ip");',
          '  return Response.json({ success });',
          '}',
        ].join('\n'),
        'app/api/health/route.ts':
          'export async function GET() { return Response.json({ ok: true }); }\n',
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-COST-002', ctx);
        expect(findings).toHaveLength(1);
        expect(findings[0]?.file).toBe('app/api/open/route.ts');
      },
    );
  });

  it('DAY2-COST-003 flags unbounded while(true) loops calling async I/O and allows bounded loops', async () => {
    await withTempRepo(
      {
        'src/loop.ts': [
          'export async function agentLoop() {',
          '  while (true) {',
          '    const res = await fetch("https://api.example.com/step");',
          '    if (res.ok) break;',
          '  }',
          '}',
          'export async function boundedLoop() {',
          '  const MAX_STEPS = 5;',
          '  let attempts = 0;',
          '  while (true) {',
          '    if (++attempts > MAX_STEPS) break;',
          '    await fetch("https://api.example.com/step");',
          '  }',
          '}',
        ].join('\n'),
      },
      async (dir) => {
        const ctx = await buildScanContext(dir);
        const findings = runRule('DAY2-COST-003', ctx);
        expect(findings).toHaveLength(1);
        expect(findings[0]?.line).toBe(2);
      },
    );
  });
});
