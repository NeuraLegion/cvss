import { BaseMetric, BaseMetricValue } from './models';
import { parseMetricsAsMap } from './parser';
import { validate } from './validator';

// https://www.first.org/cvss/v3.1/specification-document#7-4-Metric-Values
const baseMetricValueScores: Record<
  BaseMetric,
  Partial<Record<BaseMetricValue, number>> | null
> = {
  [BaseMetric.ATTACK_VECTOR]: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  [BaseMetric.ATTACK_COMPLEXITY]: { L: 0.77, H: 0.44 },
  [BaseMetric.PRIVILEGES_REQUIRED]: null, // scope-dependent: see getPrivilegesRequiredNumericValue()
  [BaseMetric.USER_INTERACTION]: { N: 0.85, R: 0.62 },
  [BaseMetric.SCOPE]: { U: 0, C: 0 },
  [BaseMetric.CONFIDENTIALITY]: { N: 0, L: 0.22, H: 0.56 },
  [BaseMetric.INTEGRITY]: { N: 0, L: 0.22, H: 0.56 },
  [BaseMetric.AVAILABILITY]: { N: 0, L: 0.22, H: 0.56 }
};

const getPrivilegesRequiredNumericValue = (
  value: BaseMetricValue,
  scopeValue: BaseMetricValue
): number => {
  if (scopeValue !== 'U' && scopeValue !== 'C') {
    throw new Error(`Unknown Scope value: ${scopeValue}`);
  }

  switch (value) {
    case 'N':
      return 0.85;
    case 'L':
      return scopeValue === 'U' ? 0.62 : 0.68;
    case 'H':
      return scopeValue === 'U' ? 0.27 : 0.5;
    default:
      throw new Error(`Unknown PrivilegesRequired value: ${value}`);
  }
};

const getMetricValue = (
  metric: BaseMetric,
  metricsMap: Map<BaseMetric, BaseMetricValue>
): BaseMetricValue => {
  if (!metricsMap.has(metric)) {
    throw new Error(`Missing metric: ${metric}`);
  }

  return metricsMap.get(metric) as BaseMetricValue;
};

const getMetricNumericValue = (
  metric: BaseMetric,
  metricsMap: Map<BaseMetric, BaseMetricValue>
): number => {
  const value = getMetricValue(metric, metricsMap);

  if (metric === BaseMetric.PRIVILEGES_REQUIRED) {
    return getPrivilegesRequiredNumericValue(
      value,
      getMetricValue(BaseMetric.SCOPE, metricsMap)
    );
  }

  const score: Partial<Record<BaseMetricValue, number>> | null =
    baseMetricValueScores[metric];
  if (score === null) {
    throw new Error(`Internal error. Missing metric score: ${metric}`);
  }

  return score[value]!;
};

// ISS = 1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]
export const calculateIss = (
  metricsMap: Map<BaseMetric, BaseMetricValue>
): number => {
  const confidentiality = getMetricNumericValue(
    BaseMetric.CONFIDENTIALITY,
    metricsMap
  );
  const integrity = getMetricNumericValue(BaseMetric.INTEGRITY, metricsMap);
  const availability = getMetricNumericValue(
    BaseMetric.AVAILABILITY,
    metricsMap
  );

  return 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability);
};

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Impact =
//   If Scope is Unchanged 	6.42 × ISS
//   If Scope is Changed 	7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)
export const calculateImpact = (
  metricsMap: Map<BaseMetric, BaseMetricValue>,
  iss: number
): number =>
  metricsMap.get(BaseMetric.SCOPE) === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
export const calculateExploitability = (
  metricsMap: Map<BaseMetric, BaseMetricValue>
): number =>
  8.22 *
  getMetricNumericValue(BaseMetric.ATTACK_VECTOR, metricsMap) *
  getMetricNumericValue(BaseMetric.ATTACK_COMPLEXITY, metricsMap) *
  getMetricNumericValue(BaseMetric.PRIVILEGES_REQUIRED, metricsMap) *
  getMetricNumericValue(BaseMetric.USER_INTERACTION, metricsMap);

// https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
const roundUp = (input: number): number => {
  const intInput = Math.round(input * 100000);

  return intInput % 10000 === 0
    ? intInput / 100000
    : (Math.floor(intInput / 10000) + 1) / 10;
};

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// If Impact <= 0 => 0; else
// If Scope is Unchanged => Roundup (Minimum [(Impact + Exploitability), 10])
// If Scope is Changed => Roundup (Minimum [1.08 × (Impact + Exploitability), 10])
export const calculateBaseScore = (cvssString: string): number => {
  validate(cvssString);

  const metricsMap: Map<BaseMetric, BaseMetricValue> = parseMetricsAsMap(
    cvssString
  );
  const iss = calculateIss(metricsMap);
  const impact = calculateImpact(metricsMap, iss);
  const exploitability = calculateExploitability(metricsMap);
  const scopeUnchanged = metricsMap.get(BaseMetric.SCOPE) === 'U';

  return impact <= 0
    ? 0
    : scopeUnchanged
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10));
};
