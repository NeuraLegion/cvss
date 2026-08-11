export enum BaseMetric {
  ATTACK_VECTOR = 'AV',
  ATTACK_COMPLEXITY = 'AC',
  ATTACK_REQUIREMENTS = 'AT',
  PRIVILEGES_REQUIRED = 'PR',
  USER_INTERACTION = 'UI',
  VULNERABLE_SYSTEM_CONFIDENTIALITY = 'VC',
  VULNERABLE_SYSTEM_INTEGRITY = 'VI',
  VULNERABLE_SYSTEM_AVAILABILITY = 'VA',
  SUBSEQUENT_SYSTEM_CONFIDENTIALITY = 'SC',
  SUBSEQUENT_SYSTEM_INTEGRITY = 'SI',
  SUBSEQUENT_SYSTEM_AVAILABILITY = 'SA'
}

export enum ThreatMetric {
  EXPLOIT_MATURITY = 'E'
}

export enum EnvironmentalMetric {
  CONFIDENTIALITY_REQUIREMENT = 'CR',
  INTEGRITY_REQUIREMENT = 'IR',
  AVAILABILITY_REQUIREMENT = 'AR',
  MODIFIED_ATTACK_VECTOR = 'MAV',
  MODIFIED_ATTACK_COMPLEXITY = 'MAC',
  MODIFIED_ATTACK_REQUIREMENTS = 'MAT',
  MODIFIED_PRIVILEGES_REQUIRED = 'MPR',
  MODIFIED_USER_INTERACTION = 'MUI',
  MODIFIED_VULNERABLE_SYSTEM_CONFIDENTIALITY = 'MVC',
  MODIFIED_VULNERABLE_SYSTEM_INTEGRITY = 'MVI',
  MODIFIED_VULNERABLE_SYSTEM_AVAILABILITY = 'MVA',
  MODIFIED_SUBSEQUENT_SYSTEM_CONFIDENTIALITY = 'MSC',
  MODIFIED_SUBSEQUENT_SYSTEM_INTEGRITY = 'MSI',
  MODIFIED_SUBSEQUENT_SYSTEM_AVAILABILITY = 'MSA'
}

export enum SupplementalMetric {
  SAFETY = 'S',
  AUTOMATABLE = 'AU',
  RECOVERY = 'R',
  VALUE_DENSITY = 'V',
  VULNERABILITY_RESPONSE_EFFORT = 'RE',
  PROVIDER_URGENCY = 'U'
}

export type Metric =
  | BaseMetric
  | ThreatMetric
  | EnvironmentalMetric
  | SupplementalMetric;

export type BaseMetricValue = 'N' | 'A' | 'L' | 'P' | 'H';

export type ThreatMetricValue = 'X' | 'A' | 'P' | 'U';

export type EnvironmentalMetricValue = BaseMetricValue | 'X' | 'M' | 'S';

export type SupplementalMetricValue =
  | 'X'
  | 'N'
  | 'P'
  | 'A'
  | 'S'
  | 'U'
  | 'I'
  | 'L'
  | 'H'
  | 'C'
  | 'Y'
  | 'D'
  | 'M'
  | 'Clear'
  | 'Green'
  | 'Amber'
  | 'Red';

export type MetricValue =
  | BaseMetricValue
  | ThreatMetricValue
  | EnvironmentalMetricValue
  | SupplementalMetricValue;

export type MetricValues<
  M extends Metric = Metric,
  V extends MetricValue = MetricValue
> = Record<M, V[]>;

export const baseMetrics: ReadonlyArray<BaseMetric> = [
  BaseMetric.ATTACK_VECTOR,
  BaseMetric.ATTACK_COMPLEXITY,
  BaseMetric.ATTACK_REQUIREMENTS,
  BaseMetric.PRIVILEGES_REQUIRED,
  BaseMetric.USER_INTERACTION,
  BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY,
  BaseMetric.VULNERABLE_SYSTEM_INTEGRITY,
  BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY,
  BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY,
  BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY,
  BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY
];

export const threatMetrics: ReadonlyArray<ThreatMetric> = [
  ThreatMetric.EXPLOIT_MATURITY
];

export const environmentalMetrics: ReadonlyArray<EnvironmentalMetric> = [
  EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
  EnvironmentalMetric.INTEGRITY_REQUIREMENT,
  EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
  EnvironmentalMetric.MODIFIED_ATTACK_VECTOR,
  EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY,
  EnvironmentalMetric.MODIFIED_ATTACK_REQUIREMENTS,
  EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED,
  EnvironmentalMetric.MODIFIED_USER_INTERACTION,
  EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_CONFIDENTIALITY,
  EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_INTEGRITY,
  EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_AVAILABILITY,
  EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_CONFIDENTIALITY,
  EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_INTEGRITY,
  EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_AVAILABILITY
];

export const supplementalMetrics: ReadonlyArray<SupplementalMetric> = [
  SupplementalMetric.SAFETY,
  SupplementalMetric.AUTOMATABLE,
  SupplementalMetric.RECOVERY,
  SupplementalMetric.VALUE_DENSITY,
  SupplementalMetric.VULNERABILITY_RESPONSE_EFFORT,
  SupplementalMetric.PROVIDER_URGENCY
];

export const baseMetricValues: MetricValues<BaseMetric, BaseMetricValue> = {
  [BaseMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P'],
  [BaseMetric.ATTACK_COMPLEXITY]: ['L', 'H'],
  [BaseMetric.ATTACK_REQUIREMENTS]: ['N', 'P'],
  [BaseMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H'],
  [BaseMetric.USER_INTERACTION]: ['N', 'P', 'A'],
  [BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY]: ['N', 'L', 'H'],
  [BaseMetric.VULNERABLE_SYSTEM_INTEGRITY]: ['N', 'L', 'H'],
  [BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY]: ['N', 'L', 'H'],
  [BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY]: ['N', 'L', 'H'],
  [BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY]: ['N', 'L', 'H'],
  [BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY]: ['N', 'L', 'H']
};

export const threatMetricValues: MetricValues<ThreatMetric, ThreatMetricValue> =
  {
    [ThreatMetric.EXPLOIT_MATURITY]: ['X', 'A', 'P', 'U']
  };

export const environmentalMetricValues: MetricValues<
  EnvironmentalMetric,
  EnvironmentalMetricValue
> = {
  [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: ['X', 'H', 'M', 'L'],
  [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: ['X', 'H', 'M', 'L'],
  [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: ['X', 'H', 'M', 'L'],
  [EnvironmentalMetric.MODIFIED_ATTACK_VECTOR]: ['X', 'N', 'A', 'L', 'P'],
  [EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY]: ['X', 'L', 'H'],
  [EnvironmentalMetric.MODIFIED_ATTACK_REQUIREMENTS]: ['X', 'N', 'P'],
  [EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED]: ['X', 'N', 'L', 'H'],
  [EnvironmentalMetric.MODIFIED_USER_INTERACTION]: ['X', 'N', 'P', 'A'],
  [EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_CONFIDENTIALITY]: [
    'X',
    'N',
    'L',
    'H'
  ],
  [EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_INTEGRITY]: [
    'X',
    'N',
    'L',
    'H'
  ],
  [EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_AVAILABILITY]: [
    'X',
    'N',
    'L',
    'H'
  ],
  [EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_CONFIDENTIALITY]: [
    'X',
    'N',
    'L',
    'H'
  ],
  [EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_INTEGRITY]: [
    'X',
    'S',
    'H',
    'L',
    'N'
  ],
  [EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_AVAILABILITY]: [
    'X',
    'S',
    'H',
    'L',
    'N'
  ]
};

export const supplementalMetricValues: MetricValues<
  SupplementalMetric,
  SupplementalMetricValue
> = {
  [SupplementalMetric.SAFETY]: ['X', 'N', 'P'],
  [SupplementalMetric.AUTOMATABLE]: ['X', 'N', 'Y'],
  [SupplementalMetric.RECOVERY]: ['X', 'A', 'U', 'I'],
  [SupplementalMetric.VALUE_DENSITY]: ['X', 'D', 'C'],
  [SupplementalMetric.VULNERABILITY_RESPONSE_EFFORT]: ['X', 'L', 'M', 'H'],
  [SupplementalMetric.PROVIDER_URGENCY]: ['X', 'Clear', 'Green', 'Amber', 'Red']
};
