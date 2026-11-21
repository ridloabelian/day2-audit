import fs from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { detectStack, parsePackageJson } from '../detector/stack-detector.js';
import { ALL_RULES } from '../rules/index.js';
import { scoreFindings } from '../scoring/scorer.js';
import type { Finding, ScanContext, ScanOptions, ScanResult } from '../types.js';
import { walkRepository } from './file-walker.js';

export async function buildScanContext(targetDir: string): Promise<ScanContext> {
  const absTarget = path.resolve(targetDir);
  const { files, allPaths, gitTrackedEnvFiles } = await walkRepository(absTarget);

  const fileMap = new Map(files.map((f) => [f.relPath, f]));
  const packageJson = parsePackageJson(files);
  const gitignoreContent = fileMap.get('.gitignore')?.content ?? '';
  const stack = detectStack(files, allPaths, packageJson);

  return {
    targetDir: absTarget,
    files,
    fileMap,
    allPaths,
    packageJson,
    gitignoreContent,
    gitTrackedEnvFiles,
    stack,
  };
}

export async function scanRepository(
  targetDir: string,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const start = performance.now();
  const absTarget = path.resolve(targetDir);

  const stat = await fs.stat(absTarget);
  if (!stat.isDirectory()) {
    throw new Error(`Target path is not a directory: ${absTarget}`);
  }

  const ctx = await buildScanContext(absTarget);
  const ignoreSet = new Set((options.ignoreRules ?? []).map((r) => r.trim().toUpperCase()));

  const activeRules = ALL_RULES.filter((rule) => {
    if (options.category && rule.category !== options.category) return false;
    if (ignoreSet.has(rule.id)) return false;
    return true;
  });

  const rawFindings: Finding[] = [];
  for (const rule of activeRules) {
    rawFindings.push(...rule.check(ctx));
  }

  const scored = scoreFindings(rawFindings);
  const durationMs = Math.max(1, Math.round(performance.now() - start));

  return {
    schemaVersion: '0.1.0',
    toolVersion: '0.1.0',
    target: absTarget,
    durationMs,
    score: scored.score,
    grade: scored.grade,
    status: scored.status,
    stack: ctx.stack,
    summary: scored.summary,
    findings: scored.findings,
  };
}
