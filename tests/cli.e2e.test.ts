import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';
import { ALL_RULES } from '../src/rules/index.js';
import type { ScanResult } from '../src/types.js';

const execFileAsync = promisify(execFile);
const ROOT_DIR = path.resolve(import.meta.dirname, '..');
const CLI_BIN = path.join(ROOT_DIR, 'dist', 'cli.js');

async function runCli(
  args: string[],
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI_BIN, ...args], {
      cwd: ROOT_DIR,
    });
    return { exitCode: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return {
      exitCode: typeof e.code === 'number' ? e.code : 1,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
    };
  }
}

describe('CLI end-to-end', () => {
  it('triggers all 15 rules on fixtures/vulnerable-vibe-app and reports score/duration in --json', async () => {
    const res = await runCli(['scan', 'fixtures/vulnerable-vibe-app', '--json']);
    expect(res.exitCode).toBe(0);

    const parsed = JSON.parse(res.stdout) as ScanResult;
    const detectedRuleIds = new Set(parsed.findings.map((f) => f.ruleId));

    for (const rule of ALL_RULES) {
      expect(detectedRuleIds.has(rule.id)).toBe(true);
    }
    expect(detectedRuleIds.size).toBe(15);
    expect(parsed.score).toBeLessThan(20);
    expect(parsed.grade).toBe('F');
    expect(parsed.durationMs).toBeLessThan(2000);
  });

  it('exits with code 1 when --fail-on critical finds critical risks', async () => {
    const res = await runCli([
      'scan',
      'fixtures/vulnerable-vibe-app',
      '--json',
      '--fail-on',
      'critical',
    ]);
    expect(res.exitCode).toBe(1);
    const parsed = JSON.parse(res.stdout) as ScanResult;
    expect(parsed.summary.critical).toBeGreaterThan(0);
  });

  it('scores fixtures/hardened-app at 100/100 and passes --fail-on medium with exit code 0', async () => {
    const res = await runCli([
      'scan',
      'fixtures/hardened-app',
      '--json',
      '--fail-on',
      'medium',
    ]);
    expect(res.exitCode).toBe(0);

    const parsed = JSON.parse(res.stdout) as ScanResult;
    expect(parsed.score).toBe(100);
    expect(parsed.grade).toBe('A');
    expect(parsed.findings).toHaveLength(0);
  });

  it('writes DAY2_REPORT.md via --markdown and outputs ready-to-paste AI remediation via --prompt', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'day2-e2e-'));
    const mdPath = path.join(tmpDir, 'DAY2_REPORT.md');

    try {
      const mdRes = await runCli([
        'scan',
        'fixtures/vulnerable-vibe-app',
        '--markdown',
        mdPath,
      ]);
      expect(mdRes.exitCode).toBe(0);
      const mdContent = await fs.readFile(mdPath, 'utf8');
      expect(mdContent).toContain('# Day-2 Production Readiness Report');
      expect(mdContent).toContain('DAY2-AUTH-001');
      expect(mdContent).toContain('app/api/generate/route.ts:');

      const promptRes = await runCli([
        'scan',
        'fixtures/vulnerable-vibe-app',
        '--prompt',
      ]);
      expect(promptRes.exitCode).toBe(0);
      for (const rule of ALL_RULES) {
        expect(promptRes.stdout).toContain(rule.id);
      }
      expect(promptRes.stdout).toContain('npx day2-audit scan . --fail-on medium');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('passes dogfood scan on the day2-audit repository itself with 100/100', async () => {
    const res = await runCli(['scan', '.', '--json', '--fail-on', 'medium']);
    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(res.stdout) as ScanResult;
    expect(parsed.score).toBe(100);
    expect(parsed.findings).toHaveLength(0);
  });
});
