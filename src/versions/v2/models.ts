export enum BaseMetric {
  ACCESS_VECTOR = 'AV',
  ACCESS_COMPLEXITY = 'AC',
  AUTHENTICATION = 'Au',
  CONFIDENTIALITY_IMPACT = 'C',
  INTEGRITY_IMPACT = 'I',
  AVAILABILITY_IMPACT = 'A'
}

export enum TemporalMetric {
  EXPLOITABILITY = 'E',
  REMEDIATION_LEVEL = 'RL',
  REPORT_CONFIDENCE = 'RC'
}

export enum EnvironmentalMetric {
  COLLATERAL_DAMAGE_POTENTIAL = 'CDP',
  TARGET_DISTRIBUTION = 'TD',
  CONFIDENTIALITY_REQUIREMENT = 'CR',
  INTEGRITY_REQUIREMENT = 'IR',
  AVAILABILITY_REQUIREMENT = 'AR'
}

// Per base metric values:
// AV: L, A, N
// AC: H, M, L
// Au: M, S, N
// C: N, P, C
// I: N, P, C
// A: N, P, C
// Union of all possible values
export type BaseMetricValue = 'N' | 'L' | 'A' | 'H' | 'M' | 'S' | 'C' | 'P';

// Per temporal metric values:
// E: U, POC, F, H, ND
// RL: OF, TF, W, U, ND
// RC: UC, UR, C, ND
// Union of all possible values
export type TemporalMetricValue =
  | 'U'
  | 'POC'
  | 'F'
  | 'H'
  | 'OF'
  | 'TF'
  | 'W'
  | 'UC'
  | 'UR'
  | 'C'
  | 'ND';

// Per environmental metric values:
// CDP: N, L, LM, MH, H, ND
// TD: N, L, M, H, ND
// CR: L, M, H, ND
// IR: L, M, H, ND
// AR: L, M, H, ND
// Union of all possible values
export type EnvironmentalMetricValue =
  | 'N'
  | 'L'
  | 'LM'
  | 'MH'
  | 'H'
  | 'M'
  | 'ND';

export type Metric = BaseMetric | TemporalMetric | EnvironmentalMetric;
export type Metrics = ReadonlyArray<Metric>;

export type MetricValue =
  | BaseMetricValue
  | TemporalMetricValue
  | EnvironmentalMetricValue;

export type MetricValues<
  M extends Metric = Metric,
  V extends MetricValue = MetricValue
> = Record<M, V[]>;

export const baseMetrics: ReadonlyArray<BaseMetric> = [
  BaseMetric.ACCESS_VECTOR,
  BaseMetric.ACCESS_COMPLEXITY,
  BaseMetric.AUTHENTICATION,
  BaseMetric.CONFIDENTIALITY_IMPACT,
  BaseMetric.INTEGRITY_IMPACT,
  BaseMetric.AVAILABILITY_IMPACT
];

export const temporalMetrics: ReadonlyArray<TemporalMetric> = [
  TemporalMetric.EXPLOITABILITY,
  TemporalMetric.REMEDIATION_LEVEL,
  TemporalMetric.REPORT_CONFIDENCE
];

export const environmentalMetrics: ReadonlyArray<EnvironmentalMetric> = [
  EnvironmentalMetric.COLLATERAL_DAMAGE_POTENTIAL,
  EnvironmentalMetric.TARGET_DISTRIBUTION,
  EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
  EnvironmentalMetric.INTEGRITY_REQUIREMENT,
  EnvironmentalMetric.AVAILABILITY_REQUIREMENT
];

export const baseMetricValues: MetricValues<BaseMetric, BaseMetricValue> = {
  [BaseMetric.ACCESS_VECTOR]: ['L', 'A', 'N'],
  [BaseMetric.ACCESS_COMPLEXITY]: ['H', 'M', 'L'],
  [BaseMetric.AUTHENTICATION]: ['M', 'S', 'N'],
  [BaseMetric.CONFIDENTIALITY_IMPACT]: ['N', 'P', 'C'],
  [BaseMetric.INTEGRITY_IMPACT]: ['N', 'P', 'C'],
  [BaseMetric.AVAILABILITY_IMPACT]: ['N', 'P', 'C']
};

export const temporalMetricValues: MetricValues<
  TemporalMetric,
  TemporalMetricValue
> = {
  [TemporalMetric.EXPLOITABILITY]: ['U', 'POC', 'F', 'H', 'ND'],
  [TemporalMetric.REMEDIATION_LEVEL]: ['OF', 'TF', 'W', 'U', 'ND'],
  [TemporalMetric.REPORT_CONFIDENCE]: ['UC', 'UR', 'C', 'ND']
};

export const environmentalMetricValues: MetricValues<
  EnvironmentalMetric,
  EnvironmentalMetricValue
> = {
  [EnvironmentalMetric.COLLATERAL_DAMAGE_POTENTIAL]: [
    'N',
    'L',
    'LM',
    'MH',
    'H',
    'ND'
  ],
  [EnvironmentalMetric.TARGET_DISTRIBUTION]: ['N', 'L', 'M', 'H', 'ND'],
  [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: ['L', 'M', 'H', 'ND'],
  [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: ['L', 'M', 'H', 'ND'],
  [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: ['L', 'M', 'H', 'ND']
};
