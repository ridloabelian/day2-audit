import path from 'node:path';
import type { ScanResult } from '../types.js';

export function renderPromptReport(result: ScanResult): string {
  const targetName = path.basename(result.target) || result.target;
  const stackSummary =
    result.stack.labels.length > 0 ? result.stack.labels.join(', ') : 'Unknown';
  const aiSummary =
    result.stack.aiSdks.length > 0 ? result.stack.aiSdks.join(', ') : 'None';

  if (result.findings.length === 0) {
    return [
      `Repository "${targetName}" already scored ${result.score}/100 on day2-audit with 0 open findings.`,
      'No remediation changes are required.',
    ].join('\n');
  }

  const lines: string[] = [
    `You are a senior production reliability & security engineer hardening the "${targetName}" repository for Day-2 production traffic.`,
    '',
    '## Current Audit Context',
    `- Detected Stack: ${stackSummary}`,
    `- AI SDKs: ${aiSummary}`,
    `- Current Day-2 Readiness Score: ${result.score}/100 (Grade ${result.grade})`,
    `- Findings: ${result.summary.critical} CRITICAL, ${result.summary.high} HIGH, ${result.summary.medium} MEDIUM`,
    '',
    '## Required Fixes (Resolve In Priority Order)',
    'Edit only the files needed to fix every finding below without breaking existing functionality or adding unnecessary dependencies.',
    '',
  ];

  result.findings.forEach((f, idx) => {
    lines.push(
      `${idx + 1}. [${f.severity}] (${f.ruleId}) \`${f.file}:${f.line}\` — ${f.title}`,
    );
    lines.push(`   - Problem: ${f.message}`);
    if (f.snippet) {
      lines.push(`   - Observed line: \`${f.snippet}\``);
    }
    lines.push(`   - Required change: ${f.remediation.replace(/\n/g, ' | ')}`);
  });

  lines.push('');
  lines.push('## Verification');
  lines.push('After applying all fixes, verify the repository passes with:');
  lines.push('```bash');
  lines.push('npx day2-audit scan . --fail-on medium');
  lines.push('```');
  lines.push('Confirm that the score improves to 100/100 with zero remaining CRITICAL, HIGH, or MEDIUM findings.');
  lines.push('');

  return lines.join('\n');
}
