import {
  BaseMetric,
  BaseMetricValue,
  EnvironmentalMetric,
  EnvironmentalMetricValue,
  Metric,
  MetricValue,
  TemporalMetric,
  TemporalMetricValue,
  environmentalMetrics,
  temporalMetrics
} from './models';
import { CvssCalculator } from '../../common/CvssCalculator';
import { CvssResultV3 } from '../../common/CvssResult';
import { parseMetricsAsMap, parseVersion } from '../../parser';

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

const temporalMetricValueScores: Record<
  TemporalMetric,
  Partial<Record<TemporalMetricValue, number>> | null
> = {
  [TemporalMetric.EXPLOIT_CODE_MATURITY]: {
    X: 1,
    U: 0.91,
    F: 0.97,
    P: 0.94,
    H: 1
  },
  [TemporalMetric.REMEDIATION_LEVEL]: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
  [TemporalMetric.REPORT_CONFIDENCE]: { X: 1, U: 0.92, R: 0.96, C: 1 }
};

const environmentalMetricValueScores: Record<
  EnvironmentalMetric,
  Partial<Record<EnvironmentalMetricValue, number>> | null
> = {
  [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: {
    M: 1,
    L: 0.5,
    H: 1.5,
    X: 1
  },
  [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: { M: 1, L: 0.5, H: 1.5, X: 1 },
  [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: {
    M: 1,
    L: 0.5,
    H: 1.5,
    X: 1
  },
  [EnvironmentalMetric.MODIFIED_ATTACK_VECTOR]:
    baseMetricValueScores[BaseMetric.ATTACK_VECTOR],
  [EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY]:
    baseMetricValueScores[BaseMetric.ATTACK_COMPLEXITY],
  [EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED]: null, // scope-dependent: see getPrivilegesRequiredNumericValue()
  [EnvironmentalMetric.MODIFIED_USER_INTERACTION]:
    baseMetricValueScores[BaseMetric.USER_INTERACTION],
  [EnvironmentalMetric.MODIFIED_SCOPE]: baseMetricValueScores[BaseMetric.SCOPE],
  [EnvironmentalMetric.MODIFIED_CONFIDENTIALITY]:
    baseMetricValueScores[BaseMetric.CONFIDENTIALITY],
  [EnvironmentalMetric.MODIFIED_INTEGRITY]:
    baseMetricValueScores[BaseMetric.INTEGRITY],
  [EnvironmentalMetric.MODIFIED_AVAILABILITY]:
    baseMetricValueScores[BaseMetric.AVAILABILITY]
};

const getPrivilegesRequiredNumericValue = (
  value: MetricValue,
  scopeValue: MetricValue
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
  metric: Metric,
  metricsMap: Map<Metric, MetricValue>
): MetricValue => {
  if (!metricsMap.has(metric)) {
    throw new Error(`Missing metric: ${metric}`);
  }

  return metricsMap.get(metric) as BaseMetricValue;
};

const getMetricNumericValue = (
  metric: Metric,
  metricsMap: Map<Metric, MetricValue>
): number => {
  const value = getMetricValue(
    (metric as BaseMetric) || TemporalMetric || EnvironmentalMetric,
    metricsMap
  );

  if (metric === BaseMetric.PRIVILEGES_REQUIRED) {
    return getPrivilegesRequiredNumericValue(
      value,
      getMetricValue(BaseMetric.SCOPE as BaseMetric, metricsMap)
    );
  }
  if (metric === EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED) {
    return getPrivilegesRequiredNumericValue(
      value,
      getMetricValue(
        EnvironmentalMetric.MODIFIED_SCOPE as EnvironmentalMetric,
        metricsMap
      )
    );
  }

  const score: Partial<Record<MetricValue, number>> | null = {
    ...baseMetricValueScores,
    ...temporalMetricValueScores,
    ...environmentalMetricValueScores
  }[metric];

  if (!score) {
    throw new Error(`Internal error. Missing metric score: ${metric}`);
  }

  return score[value]!;
};

// ISS = 1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]
export const calculateIss = (metricsMap: Map<Metric, MetricValue>): number => {
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

// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// MISS = Minimum ( 1 - [ (1 - ConfidentialityRequirement × ModifiedConfidentiality) × (1 - IntegrityRequirement × ModifiedIntegrity) × (1 - AvailabilityRequirement × ModifiedAvailability) ], 0.915)
export const calculateMiss = (metricsMap: Map<Metric, MetricValue>): number => {
  const rConfidentiality = getMetricNumericValue(
    EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
    metricsMap
  );
  const mConfidentiality = getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_CONFIDENTIALITY,
    metricsMap
  );

  const rIntegrity = getMetricNumericValue(
    EnvironmentalMetric.INTEGRITY_REQUIREMENT,
    metricsMap
  );
  const mIntegrity = getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_INTEGRITY,
    metricsMap
  );

  const rAvailability = getMetricNumericValue(
    EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
    metricsMap
  );
  const mAvailability = getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_AVAILABILITY,
    metricsMap
  );

  return Math.min(
    1 -
      (1 - rConfidentiality * mConfidentiality) *
        (1 - rIntegrity * mIntegrity) *
        (1 - rAvailability * mAvailability),
    0.915
  );
};

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Impact =
//   If Scope is Unchanged 	6.42 × ISS
//   If Scope is Changed 	7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15
export const calculateImpact = (
  metricsMap: Map<Metric, MetricValue>,
  iss: number
): number =>
  metricsMap.get(BaseMetric.SCOPE) === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

// https://www.first.org/cvss/v3-0/specification-document#8-1-Base
// ModifiedImpact =
// If ModifiedScope is Unchanged	6.42 × MISS
// If ModifiedScope is Changed	7.52 × (MISS - 0.029) - 3.25 × (MISS - 0.02)^15
// ModifiedExploitability =	8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
const calculateModifiedImpactV3 = (
  metricsMap: Map<Metric, MetricValue>,
  miss: number
): number =>
  metricsMap.get(EnvironmentalMetric.MODIFIED_SCOPE) === 'U'
    ? 6.42 * miss
    : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 1 - 0.02, 15);

// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// ModifiedImpact =
// If ModifiedScope is Unchanged	6.42 × MISS
// If ModifiedScope is Changed	7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
// ModifiedExploitability =	8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
const calculateModifiedImpactV31 = (
  metricsMap: Map<Metric, MetricValue>,
  miss: number
): number =>
  metricsMap.get(EnvironmentalMetric.MODIFIED_SCOPE) === 'U'
    ? 6.42 * miss
    : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);

export const calculateModifiedImpact = (
  metricsMap: Map<Metric, MetricValue>,
  miss: number,
  versionStr: string | null
): number =>
  versionStr === '3.0'
    ? calculateModifiedImpactV3(metricsMap, miss)
    : calculateModifiedImpactV31(metricsMap, miss);

// https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
// Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
export const calculateExploitability = (
  metricsMap: Map<Metric, MetricValue>
): number =>
  8.22 *
  getMetricNumericValue(BaseMetric.ATTACK_VECTOR, metricsMap) *
  getMetricNumericValue(BaseMetric.ATTACK_COMPLEXITY, metricsMap) *
  getMetricNumericValue(BaseMetric.PRIVILEGES_REQUIRED, metricsMap) *
  getMetricNumericValue(BaseMetric.USER_INTERACTION, metricsMap);

// https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations
// Exploitability = 8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
export const calculateModifiedExploitability = (
  metricsMap: Map<Metric, MetricValue>
): number =>
  8.22 *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_ATTACK_VECTOR,
    metricsMap
  ) *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY,
    metricsMap
  ) *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED,
    metricsMap
  ) *
  getMetricNumericValue(
    EnvironmentalMetric.MODIFIED_USER_INTERACTION,
    metricsMap
  );

// https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
export const roundUp = (input: number): number => {
  const intInput = Math.round(input * 100000);

  return intInput % 10000 === 0
    ? intInput / 100000
    : (Math.floor(intInput / 10000) + 1) / 10;
};

const round = (input: number): number => {
  const intInput = Math.round(input * 100000);

  return Math.round(intInput / 10000) / 10;
};

export const modifiedMetricsMap: { [key: string]: BaseMetric } = {
  MAV: BaseMetric.ATTACK_VECTOR,
  MAC: BaseMetric.ATTACK_COMPLEXITY,
  MPR: BaseMetric.PRIVILEGES_REQUIRED,
  MUI: BaseMetric.USER_INTERACTION,
  MS: BaseMetric.SCOPE,
  MC: BaseMetric.CONFIDENTIALITY,
  MI: BaseMetric.INTEGRITY,
  MA: BaseMetric.AVAILABILITY
};

// When Modified Temporal metric value is 'Not Defined' ('X'), which is the default value,
// then Base metric value should be used.
export const populateTemporalMetricDefaults = (
  metricsMap: Map<Metric, MetricValue>
): Map<Metric, MetricValue> => {
  [...temporalMetrics].forEach((metric) => {
    if (!metricsMap.has(metric)) {
      metricsMap.set(metric, 'X');
    }
  });

  return metricsMap;
};

export const populateEnvironmentalMetricDefaults = (
  metricsMap: Map<Metric, MetricValue>
): Map<Metric, MetricValue> => {
  [...environmentalMetrics].forEach((metric: EnvironmentalMetric) => {
    if (!metricsMap.has(metric)) {
      metricsMap.set(metric, 'X');
    }

    if (metricsMap.get(metric) === 'X') {
      metricsMap.set(
        metric,
        metricsMap.has(modifiedMetricsMap[metric])
          ? (metricsMap.get(modifiedMetricsMap[metric]) as MetricValue)
          : 'X'
      );
    }
  });

  return metricsMap;
};

export class CvssV3Calculator implements CvssCalculator {
  public calculate(cvssString: string): CvssResultV3 {
    const metricsMap = parseMetricsAsMap(cvssString) as Map<
      Metric,
      MetricValue
    >;
    const versionStr = parseVersion(cvssString)!;

    const baseResult = this.calculateBaseScore(metricsMap, versionStr);
    const temporalResult = this.calculateTemporalScore(baseResult);
    const environmentalResult = this.calculateEnvironmentalScore(
      metricsMap,
      versionStr
    );

    return {
      ...baseResult,
      ...temporalResult,
      ...environmentalResult
    };
  }

  /**
   * Calculate the base score for a CVSS v3.x string
   */
  private calculateBaseScore(
    metricsMap: Map<Metric, MetricValue>,
    versionStr: string
  ): CvssResultV3 {
    const iss = calculateIss(metricsMap);
    const impact = calculateImpact(metricsMap, iss);
    const exploitability = calculateExploitability(metricsMap);
    const scopeUnchanged = metricsMap.get(BaseMetric.SCOPE) === 'U';

    const baseScore =
      impact <= 0
        ? 0
        : scopeUnchanged
        ? roundUp(Math.min(impact + exploitability, 10))
        : roundUp(Math.min(1.08 * (impact + exploitability), 10));

    return {
      version: versionStr as '3.0' | '3.1',
      baseScore,
      baseImpact: impact <= 0 ? 0 : round(impact),
      baseExploitability: exploitability <= 0 ? 0 : round(exploitability),
      metrics: metricsMap
    };
  }

  /**
   * Calculate the temporal score for a CVSS v3.x string
   */
  private calculateTemporalScore(
    baseResult: CvssResultV3
  ): Pick<CvssResultV3, 'temporalScore'> {
    // populate temp metrics
    const metricsMap = populateTemporalMetricDefaults(
      baseResult.metrics as Map<Metric, MetricValue>
    );

    const temporalScore = roundUp(
      baseResult.baseScore *
        getMetricNumericValue(TemporalMetric.REPORT_CONFIDENCE, metricsMap) *
        getMetricNumericValue(
          TemporalMetric.EXPLOIT_CODE_MATURITY,
          metricsMap
        ) *
        getMetricNumericValue(TemporalMetric.REMEDIATION_LEVEL, metricsMap)
    );

    return {
      temporalScore
    };
  }

  /**
   * Calculate the environmental score for a CVSS v3.x string
   */
  private calculateEnvironmentalScore(
    metricsMap: Map<Metric, MetricValue>,
    versionStr: string
  ): Pick<
    CvssResultV3,
    'environmentalScore' | 'modifiedImpact' | 'modifiedExploitability'
  > {
    metricsMap = populateTemporalMetricDefaults(metricsMap);
    metricsMap = populateEnvironmentalMetricDefaults(metricsMap);

    const miss = calculateMiss(metricsMap);
    const impact = calculateModifiedImpact(metricsMap, miss, versionStr);
    const exploitability = calculateModifiedExploitability(metricsMap);
    const scopeUnchanged =
      metricsMap.get(EnvironmentalMetric.MODIFIED_SCOPE) === 'U';

    const environmentalScore =
      impact <= 0
        ? 0
        : scopeUnchanged
        ? roundUp(
            roundUp(Math.min(impact + exploitability, 10)) *
              getMetricNumericValue(
                TemporalMetric.EXPLOIT_CODE_MATURITY,
                metricsMap
              ) *
              getMetricNumericValue(
                TemporalMetric.REMEDIATION_LEVEL,
                metricsMap
              ) *
              getMetricNumericValue(
                TemporalMetric.REPORT_CONFIDENCE,
                metricsMap
              )
          )
        : roundUp(
            roundUp(Math.min(1.08 * (impact + exploitability), 10)) *
              getMetricNumericValue(
                TemporalMetric.EXPLOIT_CODE_MATURITY,
                metricsMap
              ) *
              getMetricNumericValue(
                TemporalMetric.REMEDIATION_LEVEL,
                metricsMap
              ) *
              getMetricNumericValue(
                TemporalMetric.REPORT_CONFIDENCE,
                metricsMap
              )
          );

    return {
      environmentalScore,
      modifiedImpact: impact <= 0 ? 0 : round(impact),
      modifiedExploitability: exploitability <= 0 ? 0 : round(exploitability)
    };
  }
}
