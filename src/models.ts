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

export type Severity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

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

export type BaseMetricValue = 'A' | 'C' | 'H' | 'L' | 'N' | 'P' | 'R' | 'U';

export const baseMetricValues: Record<BaseMetric, BaseMetricValue[]> = {
  [BaseMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P'],
  [BaseMetric.ATTACK_COMPLEXITY]: ['L', 'H'],
  [BaseMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H'],
  [BaseMetric.USER_INTERACTION]: ['N', 'R'],
  [BaseMetric.SCOPE]: ['U', 'C'],
  [BaseMetric.CONFIDENTIALITY]: ['N', 'L', 'H'],
  [BaseMetric.INTEGRITY]: ['N', 'L', 'H'],
  [BaseMetric.AVAILABILITY]: ['N', 'L', 'H']
};
