import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export async function withTempRepo<T>(
  files: Record<string, string>,
  fn: (dir: string) => Promise<T>,
): Promise<T> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'day2-audit-test-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const fullPath = path.join(dir, rel);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, content, 'utf8');
    }
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}
