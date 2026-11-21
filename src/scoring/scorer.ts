import {
  CATEGORIES,
  CATEGORY_ORDER,
  type CategoryId,
  type CategorySummary,
  type Finding,
  type Grade,
  type ReadinessStatus,
  type ScanSummary,
  type Severity,
} from '../types.js';

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 15,
  HIGH: 8,
  MEDIUM: 4,
};

const RULE_CAP: Record<Severity, number> = {
  CRITICAL: 30,
  HIGH: 16,
  MEDIUM: 8,
};

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const ruleDiff = a.ruleId.localeCompare(b.ruleId);
    if (ruleDiff !== 0) return ruleDiff;
    const fileDiff = a.file.localeCompare(b.file);
    if (fileDiff !== 0) return fileDiff;
    return a.line - b.line;
  });
}

function computeRuleCappedDeduction(findings: Finding[]): number {
  const byRule = new Map<string, { severity: Severity; total: number }>();
  for (const f of findings) {
    const cur = byRule.get(f.ruleId);
    const weight = SEVERITY_WEIGHT[f.severity];
    if (!cur) {
      byRule.set(f.ruleId, { severity: f.severity, total: weight });
    } else {
      cur.total += weight;
    }
  }

  let deduction = 0;
  for (const entry of byRule.values()) {
    deduction += Math.min(entry.total, RULE_CAP[entry.severity]);
  }
  return deduction;
}

export function scoreFindings(rawFindings: Finding[]): {
  findings: Finding[];
  score: number;
  grade: Grade;
  status: ReadinessStatus;
  summary: ScanSummary;
} {
  const findings = sortFindings(rawFindings);
  const overallDeduction = computeRuleCappedDeduction(findings);
  const score = Math.max(0, Math.min(100, 100 - overallDeduction));

  let grade: Grade;
  let status: ReadinessStatus;
  if (score >= 90) {
    grade = 'A';
    status = 'PRODUCTION_READY';
  } else if (score >= 75) {
    grade = 'B';
    status = 'CAUTION';
  } else if (score >= 50) {
    grade = 'C';
    status = 'AT_RISK';
  } else {
    grade = 'F';
    status = 'CRITICAL_RISK';
  }

  const byCategory = {} as Record<CategoryId, CategorySummary>;
  for (const catId of CATEGORY_ORDER) {
    const catFindings = findings.filter((f) => f.category === catId);
    const catDeduction = computeRuleCappedDeduction(catFindings);
    byCategory[catId] = {
      label: CATEGORIES[catId],
      findings: catFindings.length,
      critical: catFindings.filter((f) => f.severity === 'CRITICAL').length,
      high: catFindings.filter((f) => f.severity === 'HIGH').length,
      medium: catFindings.filter((f) => f.severity === 'MEDIUM').length,
      score: Math.max(0, Math.min(100, 100 - catDeduction)),
    };
  }

  const summary: ScanSummary = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'CRITICAL').length,
    high: findings.filter((f) => f.severity === 'HIGH').length,
    medium: findings.filter((f) => f.severity === 'MEDIUM').length,
    byCategory,
  };

  return { findings, score, grade, status, summary };
}
