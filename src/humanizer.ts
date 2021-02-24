import { BaseMetric, BaseMetricValue } from './models';

export const humanizeBaseMetric = (baseMetric: BaseMetric): string => {
  switch (baseMetric) {
    case BaseMetric.ATTACK_VECTOR:
      return 'Attack Vector';
    case BaseMetric.ATTACK_COMPLEXITY:
      return 'Attack Complexity';
    case BaseMetric.PRIVILEGES_REQUIRED:
      return 'Privileges Required';
    case BaseMetric.USER_INTERACTION:
      return 'User Interaction';
    case BaseMetric.SCOPE:
      return 'Scope';
    case BaseMetric.CONFIDENTIALITY:
      return 'Confidentiality';
    case BaseMetric.INTEGRITY:
      return 'Integrity';
    case BaseMetric.AVAILABILITY:
      return 'Availability';
    default:
      return 'Unknown';
  }
};

// eslint-disable-next-line complexity
export const humanizeBaseMetricValue = (
  value: BaseMetricValue,
  metric: BaseMetric
): string => {
  switch (value) {
    case 'A':
      return 'Adjacent';
    case 'C':
      return 'Changed';
    case 'H':
      return 'High';
    case 'L':
      return metric === BaseMetric.ATTACK_VECTOR ? 'Local' : 'Low';
    case 'N':
      return metric === BaseMetric.ATTACK_VECTOR ? 'Network' : 'None';
    case 'P':
      return 'Physical';
    case 'R':
      return 'Required';
    case 'U':
      return 'Unchanged';
    default:
      return 'Unknown';
  }
};

/**
 * Stringify a score into a qualitative severity rating string
 * @param score
 */
export const humanizeScore = (score: number): string =>
  score <= 0
    ? 'None'
    : score <= 3.9
    ? 'Low'
    : score <= 6.9
    ? 'Medium'
    : score <= 8.9
    ? 'High'
    : 'Critical';
