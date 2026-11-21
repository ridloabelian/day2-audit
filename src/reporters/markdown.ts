import path from 'node:path';
import { CATEGORY_ORDER, type ScanResult } from '../types.js';

export function renderMarkdownReport(result: ScanResult): string {
  const targetName = path.basename(result.target) || result.target;
  const stackSummary =
    result.stack.labels.length > 0 ? result.stack.labels.join(', ') : 'Generic Repository';
  const aiSummary =
    result.stack.aiSdks.length > 0 ? result.stack.aiSdks.join(', ') : 'None detected';

  const lines: string[] = [
    `# Day-2 Production Readiness Report — \`${targetName}\``,
    '',
    `- **Tool:** \`day2-audit\` v${result.toolVersion}`,
    `- **Score:** **${result.score}/100** (Grade **${result.grade}**, Status: \`${result.status}\`)`,
    `- **Detected Stack:** ${stackSummary}`,
    `- **AI SDKs:** ${aiSummary}`,
    `- **Scan Duration:** ${result.durationMs}ms`,
    '',
    '## Severity Summary',
    '',
    '| Severity | Count |',
    '| --- | ---: |',
    `| CRITICAL | ${result.summary.critical} |`,
    `| HIGH | ${result.summary.high} |`,
    `| MEDIUM | ${result.summary.medium} |`,
    `| **Total** | **${result.summary.total}** |`,
    '',
    '## Category Scorecard',
    '',
    '| Category | Score | Findings | Critical | High | Medium |',
    '| --- | ---: | ---: | ---: | ---: | ---: |',
  ];

  for (const catId of CATEGORY_ORDER) {
    const cat = result.summary.byCategory[catId];
    lines.push(
      `| ${cat.label} | ${cat.score}/100 | ${cat.findings} | ${cat.critical} | ${cat.high} | ${cat.medium} |`,
    );
  }

  lines.push('');
  lines.push('## Findings & Remediation');
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No Day-2 production readiness risks detected.');
    lines.push('');
    return lines.join('\n');
  }

  for (const f of result.findings) {
    lines.push(`### [${f.severity}] \`${f.ruleId}\` — ${f.title}`);
    lines.push('');
    lines.push(`- **Location:** \`${f.file}:${f.line}\``);
    lines.push(`- **Category:** ${f.categoryLabel}`);
    lines.push(`- **Issue:** ${f.message}`);
    if (f.snippet) {
      lines.push(`- **Code:** \`${f.snippet}\``);
    }
    lines.push('');
    lines.push('**Recommended Fix:**');
    lines.push('');
    lines.push('```text');
    lines.push(f.remediation);
    lines.push('```');
    lines.push('');
  }

  return lines.join('\n');
}
