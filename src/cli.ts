#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import { renderJsonReport } from './reporters/json.js';
import { renderMarkdownReport } from './reporters/markdown.js';
import { renderPromptReport } from './reporters/prompt.js';
import { renderTerminalReport } from './reporters/terminal.js';
import { ALL_RULES } from './rules/index.js';
import { scanRepository } from './scanner/engine.js';
import { CATEGORY_ORDER, type CategoryId, type FailOnLevel, type ScanResult } from './types.js';

const VALID_FAIL_ON = new Set<FailOnLevel>(['critical', 'high', 'medium', 'none']);

function shouldFail(result: ScanResult, failOn: FailOnLevel): boolean {
  switch (failOn) {
    case 'critical':
      return result.summary.critical > 0;
    case 'high':
      return result.summary.critical + result.summary.high > 0;
    case 'medium':
      return result.summary.total > 0;
    case 'none':
      return false;
  }
}

interface ScanCliOptions {
  json?: boolean;
  markdown?: string | boolean;
  prompt?: string | boolean;
  failOn: string;
  category?: string;
  ignoreRule?: string;
}

const program = new Command();

program
  .name('day2-audit')
  .description('Fast offline Day-2 production readiness scanner for vibe-coded web & AI repositories')
  .version('0.1.0');

program
  .command('scan', { isDefault: true })
  .description('Audit a repository directory for Day-2 production readiness risks')
  .argument('[target]', 'Target directory to scan', '.')
  .option('--json', 'Output scan results as JSON')
  .option('--markdown [file]', 'Write Markdown report (default: DAY2_REPORT.md, or "-" for stdout)')
  .option('--prompt [file]', 'Generate a copy-paste AI coding agent remediation prompt')
  .option(
    '--fail-on <level>',
    'Exit with code 1 when findings meet threshold (critical|high|medium|none)',
    'none',
  )
  .option('--category <id>', `Filter rules by category (${CATEGORY_ORDER.join('|')})`)
  .option('--ignore-rule <ids>', 'Comma-separated rule IDs to ignore')
  .action(async (target: string, opts: ScanCliOptions) => {
    const failOnRaw = opts.failOn.toLowerCase() as FailOnLevel;
    if (!VALID_FAIL_ON.has(failOnRaw)) {
      console.error(
        pc.red(`Invalid --fail-on value "${opts.failOn}". Expected critical, high, medium, or none.`),
      );
      process.exitCode = 2;
      return;
    }

    let categoryFilter: CategoryId | undefined;
    if (opts.category) {
      if (!CATEGORY_ORDER.includes(opts.category as CategoryId)) {
        console.error(
          pc.red(
            `Invalid --category "${opts.category}". Expected one of: ${CATEGORY_ORDER.join(', ')}.`,
          ),
        );
        process.exitCode = 2;
        return;
      }
      categoryFilter = opts.category as CategoryId;
    }

    const ignoreRules = opts.ignoreRule
      ? opts.ignoreRule.split(',').map((s) => s.trim()).filter(Boolean)
      : [];

    let result: ScanResult;
    try {
      result = await scanRepository(target, {
        category: categoryFilter,
        ignoreRules,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`Scan failed: ${msg}`));
      process.exitCode = 2;
      return;
    }

    let wroteStdoutReport = false;

    if (opts.markdown !== undefined) {
      const mdContent = renderMarkdownReport(result);
      if (opts.markdown === '-') {
        process.stdout.write(mdContent);
        wroteStdoutReport = true;
      } else {
        const outFile =
          typeof opts.markdown === 'string'
            ? path.resolve(opts.markdown)
            : path.resolve(process.cwd(), 'DAY2_REPORT.md');
        await fs.mkdir(path.dirname(outFile), { recursive: true });
        await fs.writeFile(outFile, mdContent, 'utf8');
        if (!opts.json && opts.prompt === undefined) {
          console.error(pc.green(`Markdown report written to ${outFile}`));
        }
      }
    }

    if (opts.prompt !== undefined) {
      const promptContent = renderPromptReport(result);
      if (typeof opts.prompt === 'string') {
        const outFile = path.resolve(opts.prompt);
        await fs.mkdir(path.dirname(outFile), { recursive: true });
        await fs.writeFile(outFile, promptContent, 'utf8');
        if (!opts.json) {
          console.error(pc.green(`AI remediation prompt written to ${outFile}`));
        }
      } else {
        process.stdout.write(promptContent);
        wroteStdoutReport = true;
      }
    }

    if (opts.json) {
      process.stdout.write(renderJsonReport(result));
    } else if (!wroteStdoutReport) {
      process.stdout.write(renderTerminalReport(result));
    }

    if (shouldFail(result, failOnRaw)) {
      process.exitCode = 1;
    }
  });

program
  .command('rules')
  .description('List all built-in Day-2 readiness rules')
  .option('--json', 'Output rules catalog as JSON')
  .action((opts: { json?: boolean }) => {
    if (opts.json) {
      const payload = ALL_RULES.map((r) => ({
        id: r.id,
        title: r.title,
        category: r.category,
        severity: r.severity,
        description: r.description,
      }));
      process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
      return;
    }

    console.log('');
    console.log(pc.bold(`day2-audit built-in rules (${ALL_RULES.length})`));
    console.log('');
    for (const rule of ALL_RULES) {
      console.log(
        `  ${pc.bold(rule.id)}  [${rule.severity}]  ${rule.title} ${pc.dim(`(${rule.category})`)}`,
      );
    }
    console.log('');
  });

await program.parseAsync(process.argv);
