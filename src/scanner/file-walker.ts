import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import type { ScannedFile } from '../types.js';

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  'dist',
  'build',
  'out',
  'coverage',
  '.turbo',
  '.vercel',
  '.wrangler',
  '__pycache__',
  '.venv',
  'venv',
  '.pytest_cache',
  'vendor',
  'target',
]);

const SKIP_TOP_LEVEL_DIRS = new Set(['fixtures']);

const BINARY_EXTS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.svg',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.pdf',
  '.zip',
  '.gz',
  '.tar',
  '.tgz',
  '.lockb',
  '.sqlite',
  '.db',
  '.wasm',
  '.pyc',
]);

const SKIP_CONTENT_FILENAMES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
  'poetry.lock',
  'uv.lock',
  'Pipfile.lock',
  'DAY2_REPORT.md',
]);

const MAX_FILE_BYTES = 1024 * 1024; // 1 MB

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

function isTestPath(relPath: string): boolean {
  return (
    /(?:^|\/)(?:__tests__|tests?)\//.test(relPath) ||
    /\.(?:test|spec)\.[jt]sx?$/.test(relPath) ||
    /(?:^|\/)test_[^/]+\.py$/.test(relPath) ||
    /_test\.py$/.test(relPath)
  );
}

function looksBinary(buf: Buffer): boolean {
  const sampleLen = Math.min(buf.length, 512);
  for (let i = 0; i < sampleLen; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

export interface WalkResult {
  files: ScannedFile[];
  allPaths: string[];
  gitTrackedEnvFiles: string[];
}

export function detectGitTrackedEnvFiles(targetDir: string): string[] {
  const gitDir = path.join(targetDir, '.git');
  if (!existsSync(gitDir)) return [];

  try {
    const stdout = execFileSync(
      'git',
      ['ls-files', '--', '.env', '.env.*', '**/.env', '**/.env.*'],
      {
        cwd: targetDir,
        timeout: 500,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      },
    );
    return stdout
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .filter((rel) => {
        const base = path.basename(rel).toLowerCase();
        return (
          base !== '.env.example' &&
          base !== '.env.sample' &&
          base !== '.env.template' &&
          base !== '.env.dist'
        );
      });
  } catch {
    return [];
  }
}

export async function walkRepository(targetDir: string): Promise<WalkResult> {
  const files: ScannedFile[] = [];
  const allPaths: string[] = [];

  async function walk(currentDir: string, depth: number): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const absPath = path.join(currentDir, entry.name);
      const relPath = toPosix(path.relative(targetDir, absPath));

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (depth === 0 && SKIP_TOP_LEVEL_DIRS.has(entry.name)) continue;
        await walk(absPath, depth + 1);
        continue;
      }

      if (!entry.isFile()) continue;

      allPaths.push(relPath);

      const base = entry.name;
      const ext = path.extname(base).toLowerCase();
      if (BINARY_EXTS.has(ext) || SKIP_CONTENT_FILENAMES.has(base)) {
        continue;
      }

      try {
        const stat = await fs.stat(absPath);
        if (stat.size > MAX_FILE_BYTES) continue;

        const buf = await fs.readFile(absPath);
        if (looksBinary(buf)) continue;

        const content = buf.toString('utf8');
        files.push({
          relPath,
          absPath,
          ext,
          isTest: isTestPath(relPath),
          content,
          lines: content.split(/\r?\n/),
        });
      } catch {
        continue;
      }
    }
  }

  await walk(targetDir, 0);
  const gitTrackedEnvFiles = detectGitTrackedEnvFiles(targetDir);

  return { files, allPaths, gitTrackedEnvFiles };
}
