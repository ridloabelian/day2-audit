import path from 'node:path';
import pc from 'picocolors';
import { CATEGORY_ORDER, type Finding, type ScanResult, type Severity } from '../types.js';

function severityBadge(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'HIGH':
      return pc.bgYellow(pc.black(pc.bold('   HIGH   ')));
    case 'MEDIUM':
      return pc.bgCyan(pc.black(pc.bold('  MEDIUM  ')));
  }
}

function renderProgressBar(score: number, width = 28): string {
  const filled = Math.round((score / 100) * width);
  const empty = Math.max(0, width - filled);
  const barColor =
    score >= 90 ? pc.green : score >= 75 ? pc.yellow : score >= 50 ? pc.yellow : pc.red;
  return `${barColor('█'.repeat(filled))}${pc.dim('░'.repeat(empty))}`;
}

function formatStatusLabel(status: ScanResult['status']): string {
  switch (status) {
    case 'PRODUCTION_READY':
      return pc.green(pc.bold('PRODUCTION READY'));
    case 'CAUTION':
      return pc.yellow(pc.bold('CAUTION'));
    case 'AT_RISK':
      return pc.yellow(pc.bold('AT RISK'));
    case 'CRITICAL_RISK':
      return pc.red(pc.bold('CRITICAL RISK'));
  }
}

function groupByRule(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = map.get(f.ruleId);
    if (arr) arr.push(f);
    else map.set(f.ruleId, [f]);
  }
  return map;
}

export function renderTerminalReport(result: ScanResult): string {
  const lines: string[] = [];
  const targetName = path.basename(result.target) || result.target;

  lines.push('');
  lines.push(
    `${pc.bold(pc.cyan('day2-audit'))} ${pc.dim(`v${result.toolVersion}`)}  ${pc.dim('•')}  Scanned ${pc.bold(targetName)} in ${pc.green(`${result.durationMs}ms`)}`,
  );

  const stackText =
    result.stack.labels.length > 0 ? result.stack.labels.join(', ') : 'Generic Repository';
  const aiText =
    result.stack.aiSdks.length > 0 ? `  |  AI SDKs: ${result.stack.aiSdks.join(', ')}` : '';
  lines.push(`${pc.dim('Stack:')} ${stackText}${aiText}`);
  lines.push(pc.dim('─'.repeat(76)));

  const scoreColor =
    result.score >= 90 ? pc.green : result.score >= 75 ? pc.yellow : pc.red;
  lines.push(
    `Day-2 Readiness Score: ${scoreColor(pc.bold(`${result.score}/100`))}  [${renderProgressBar(result.score)}]  Grade ${scoreColor(pc.bold(result.grade))}  (${formatStatusLabel(result.status)})`,
  );
  lines.push(
    `Findings: ${pc.red(pc.bold(`${result.summary.critical} CRITICAL`))}  ${pc.dim('•')}  ${pc.yellow(pc.bold(`${result.summary.high} HIGH`))}  ${pc.dim('•')}  ${pc.cyan(pc.bold(`${result.summary.medium} MEDIUM`))}  ${pc.dim(`(${result.summary.total} total)`)}`,
  );
  lines.push('');

  lines.push(pc.bold('Category Scorecard'));
  for (const catId of CATEGORY_ORDER) {
    const cat = result.summary.byCategory[catId];
    const labelPad = cat.label.padEnd(28, ' ');
    const catColor = cat.score >= 90 ? pc.green : cat.score >= 70 ? pc.yellow : pc.red;
    const scoreStr = catColor(`${String(cat.score).padStart(3, ' ')}/100`);
    const countStr =
      cat.findings === 0
        ? pc.green('PASS')
        : pc.dim(`${cat.findings} issue${cat.findings === 1 ? '' : 's'}`);
    lines.push(`  ${labelPad} ${scoreStr}   ${countStr}`);
  }

  if (result.findings.length === 0) {
    lines.push('');
    lines.push(pc.green(pc.bold('✓ No Day-2 readiness gaps detected. Ready for production!')));
    lines.push('');
    return lines.join('\n');
  }

  lines.push('');
  lines.push(pc.bold('Detected Risks & Copy-Paste Remediations'));
  lines.push(pc.dim('─'.repeat(76)));

  const grouped = groupByRule(result.findings);
  for (const [ruleId, items] of grouped.entries()) {
    const head = items[0]!;
    lines.push('');
    lines.push(
      `${severityBadge(head.severity)} ${pc.bold(ruleId)} ${pc.bold(head.title)} ${pc.dim(`(${head.categoryLabel})`)}`,
    );

    for (const item of items) {
      lines.push(`  ${pc.yellow('→')} ${pc.bold(`${item.file}:${item.line}`)} ${pc.dim('—')} ${item.message}`);
      if (item.snippet) {
        lines.push(`    ${pc.dim('|')} ${pc.dim(item.snippet)}`);
      }
    }

    const uniqueRemediations = Array.from(new Set(items.map((item) => item.remediation)));
    lines.push(`  ${pc.green('Fix:')}`);
    uniqueRemediations.forEach((remediation, idx) => {
      if (idx > 0) lines.push('');
      for (const remLine of remediation.split('\n')) {
        lines.push(`    ${pc.cyan(remLine)}`);
      }
    });
  }

  lines.push('');
  lines.push(
    pc.dim('Tip: Run with `--prompt` to generate a ready-to-paste AI agent fix prompt, or `--markdown` for DAY2_REPORT.md.'),
  );
  lines.push('');

  return lines.join('\n');
}
