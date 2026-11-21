export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM';

export type FailOnLevel = 'critical' | 'high' | 'medium' | 'none';

export type CategoryId =
  | 'auth-data'
  | 'cost-abuse'
  | 'api-safety'
  | 'reliability'
  | 'ops-hygiene';

export const CATEGORIES: Record<CategoryId, string> = {
  'auth-data': 'Auth & Data Exposure',
  'cost-abuse': 'Cost & Abuse Protection',
  'api-safety': 'API & Webhook Safety',
  'reliability': 'Reliability & Resilience',
  'ops-hygiene': 'Ops & Dependency Hygiene',
};

export const CATEGORY_ORDER: CategoryId[] = [
  'auth-data',
  'cost-abuse',
  'api-safety',
  'reliability',
  'ops-hygiene',
];

export type DetectedStackId =
  | 'nextjs'
  | 'react'
  | 'node-api'
  | 'supabase'
  | 'prisma'
  | 'drizzle'
  | 'cloudflare-workers'
  | 'docker'
  | 'python-fastapi';

export interface StackProfile {
  stacks: DetectedStackId[];
  labels: string[];
  aiSdks: string[];
  nextjsRouter?: 'app' | 'pages' | 'hybrid';
  hasLockfile: boolean;
  lockfiles: string[];
}

export interface ScannedFile {
  relPath: string;
  absPath: string;
  ext: string;
  isTest: boolean;
  content: string;
  lines: string[];
}

export interface PackageJsonContext {
  raw: ScannedFile;
  data: Record<string, unknown>;
}

export interface ScanContext {
  targetDir: string;
  files: ScannedFile[];
  fileMap: Map<string, ScannedFile>;
  allPaths: string[];
  packageJson?: PackageJsonContext;
  gitignoreContent: string;
  gitTrackedEnvFiles: string[];
  stack: StackProfile;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: CategoryId;
  categoryLabel: string;
  severity: Severity;
  file: string;
  line: number;
  message: string;
  snippet?: string;
  remediation: string;
}

export interface Rule {
  id: string;
  title: string;
  category: CategoryId;
  severity: Severity;
  description: string;
  check(ctx: ScanContext): Finding[];
}

export interface CategorySummary {
  label: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  score: number;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  byCategory: Record<CategoryId, CategorySummary>;
}

export type Grade = 'A' | 'B' | 'C' | 'F';

export type ReadinessStatus =
  | 'PRODUCTION_READY'
  | 'CAUTION'
  | 'AT_RISK'
  | 'CRITICAL_RISK';

export interface ScanResult {
  schemaVersion: '0.1.0';
  toolVersion: '0.1.0';
  target: string;
  durationMs: number;
  score: number;
  grade: Grade;
  status: ReadinessStatus;
  stack: StackProfile;
  summary: ScanSummary;
  findings: Finding[];
}

export interface ScanOptions {
  category?: CategoryId;
  ignoreRules?: string[];
}
