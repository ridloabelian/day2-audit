import { apiSafetyRules } from './api-safety.js';
import { authDataRules } from './auth-data.js';
import { costAbuseRules } from './cost-abuse.js';
import { opsHygieneRules } from './ops-hygiene.js';
import { reliabilityRules } from './reliability.js';
import type { Rule } from '../types.js';

export const ALL_RULES: Rule[] = [
  ...authDataRules,
  ...costAbuseRules,
  ...apiSafetyRules,
  ...reliabilityRules,
  ...opsHygieneRules,
];

export {
  authDataRules,
  costAbuseRules,
  apiSafetyRules,
  reliabilityRules,
  opsHygieneRules,
};
