export enum BaseMetric {
  ATTACK_VECTOR = 'AV',
  ATTACK_COMPLEXITY = 'AC',
  PRIVILEGES_REQUIRED = 'PR',
  USER_INTERACTION = 'UI',
  SCOPE = 'S',
  CONFIDENTIALITY = 'C',
  INTEGRITY = 'I',
  AVAILABILITY = 'A'
}

export enum TemporalMetric {
  EXPLOITABILITY = 'E',
  REMEDIATION_LEVEL = 'RL',
  REPORT_CONFIDENCE = 'RC'
}

export enum EnvironmentalMetric {
  ATTACK_VECTOR = 'MAV',
  ATTACK_COMPLEXITY = 'MAC',
  PRIVILEGES_REQUIRED = 'MPR',
  USER_INTERACTION = 'MUI',
  SCOPE = 'MS',
  CONFIDENTIALITY = 'MC',
  INTEGRITY = 'MI',
  AVAILABILITY = 'MA',
  CONFIDENTIALITY_REQUIREMENT = 'CR',
  INTEGRITY_REQUIREMENT = 'IR',
  AVAILABILITY_REQUIREMENT = 'AR'
}

export const baseMetrics: ReadonlyArray<BaseMetric> = [
  BaseMetric.ATTACK_VECTOR,
  BaseMetric.ATTACK_COMPLEXITY,
  BaseMetric.PRIVILEGES_REQUIRED,
  BaseMetric.USER_INTERACTION,
  BaseMetric.SCOPE,
  BaseMetric.CONFIDENTIALITY,
  BaseMetric.INTEGRITY,
  BaseMetric.AVAILABILITY
];

export const temporalMetrics: Metrics<TemporalMetric> = [
  TemporalMetric.EXPLOITABILITY,
  TemporalMetric.REMEDIATION_LEVEL,
  TemporalMetric.REPORT_CONFIDENCE
];

export const environmentalMetrics: Metrics<EnvironmentalMetric> = [
  EnvironmentalMetric.ATTACK_VECTOR,
  EnvironmentalMetric.ATTACK_COMPLEXITY,
  EnvironmentalMetric.PRIVILEGES_REQUIRED,
  EnvironmentalMetric.USER_INTERACTION,
  EnvironmentalMetric.SCOPE,
  EnvironmentalMetric.CONFIDENTIALITY,
  EnvironmentalMetric.INTEGRITY,
  EnvironmentalMetric.AVAILABILITY,
  EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
  EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
  EnvironmentalMetric.INTEGRITY_REQUIREMENT
];

export const baseMetricValues: MetricValues<BaseMetric, BaseMetricValue> = {
  [BaseMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P'],
  [BaseMetric.ATTACK_COMPLEXITY]: ['L', 'H'],
  [BaseMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H'],
  [BaseMetric.USER_INTERACTION]: ['N', 'R'],
  [BaseMetric.SCOPE]: ['U', 'C'],
  [BaseMetric.CONFIDENTIALITY]: ['N', 'L', 'H'],
  [BaseMetric.INTEGRITY]: ['N', 'L', 'H'],
  [BaseMetric.AVAILABILITY]: ['N', 'L', 'H']
};

export const environmentalMetricValues: MetricValues<
  EnvironmentalMetric,
  EnvironmentalMetricValue
> = {
  [EnvironmentalMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P', 'X'],
  [EnvironmentalMetric.ATTACK_COMPLEXITY]: ['L', 'H', 'X'],
  [EnvironmentalMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H', 'X'],
  [EnvironmentalMetric.USER_INTERACTION]: ['N', 'R', 'X'],
  [EnvironmentalMetric.SCOPE]: ['U', 'C', 'X'],
  [EnvironmentalMetric.CONFIDENTIALITY]: ['N', 'L', 'H', 'X'],
  [EnvironmentalMetric.INTEGRITY]: ['N', 'L', 'H', 'X'],
  [EnvironmentalMetric.AVAILABILITY]: ['N', 'L', 'H', 'X'],
  [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: ['M', 'L', 'H', 'X'],
  [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: ['M', 'L', 'H', 'X'],
  [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: ['M', 'L', 'H', 'X']
};

export const temporalMetricValues: MetricValues<
  TemporalMetric,
  TemporalMetricValue
> = {
  [TemporalMetric.EXPLOITABILITY]: ['X', 'U', 'P', 'F', 'H'],
  [TemporalMetric.REMEDIATION_LEVEL]: ['X', 'O', 'T', 'W', 'U'],
  [TemporalMetric.REPORT_CONFIDENCE]: ['X', 'U', 'R', 'C']
};

export const metricsIndex: { [key: string]: BaseMetric } = {
  MAV: BaseMetric.ATTACK_VECTOR,
  MAC: BaseMetric.ATTACK_COMPLEXITY,
  MPR: BaseMetric.PRIVILEGES_REQUIRED,
  MUI: BaseMetric.USER_INTERACTION,
  MS: BaseMetric.SCOPE,
  MC: BaseMetric.CONFIDENTIALITY,
  MI: BaseMetric.INTEGRITY,
  MA: BaseMetric.AVAILABILITY
};

export type Metric = BaseMetric | TemporalMetric | EnvironmentalMetric;
export type AnyMetric = BaseMetric & TemporalMetric & EnvironmentalMetric;
export type BaseMetricValue = 'A' | 'C' | 'H' | 'L' | 'N' | 'P' | 'R' | 'U';
export type TemporalMetricValue =
  | 'X'
  | 'F'
  | 'H'
  | 'O'
  | 'T'
  | 'W'
  | 'U'
  | 'P'
  | 'C'
  | 'R';
export type EnvironmentalMetricValue = BaseMetricValue | 'M' | 'X';
export type MetricValue =
  | BaseMetricValue
  | TemporalMetricValue
  | EnvironmentalMetricValue
  | any;
export type MetricValues<
  M extends Metric = Metric,
  V extends MetricValue = MetricValue
> = Record<M, V[]>;
export type Metrics<M = Metric> = ReadonlyArray<M>;
export type AllMetricValues =
  | typeof baseMetricValues
  | typeof temporalMetricValues
  | typeof environmentalMetricValues;

export type ScoreResult = {
  score: number;
  impact: number;
  exploitability: number;
  metricsMap: Map<Metric, MetricValue>;
};
