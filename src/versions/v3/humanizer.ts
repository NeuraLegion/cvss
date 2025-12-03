import {
  BaseMetric,
  EnvironmentalMetric,
  Metric,
  MetricValue,
  TemporalMetric
} from './models';

// eslint-disable-next-line complexity
export const humanizeMetric = (metric: Metric): string => {
  switch (metric) {
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
    case TemporalMetric.EXPLOIT_CODE_MATURITY:
      return 'Exploit Code Maturity';
    case TemporalMetric.REMEDIATION_LEVEL:
      return 'Remediation Level';
    case TemporalMetric.REPORT_CONFIDENCE:
      return 'Report Confidence';
    case EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT:
      return 'Confidentiality Requirement';
    case EnvironmentalMetric.INTEGRITY_REQUIREMENT:
      return 'Integrity Requirement';
    case EnvironmentalMetric.AVAILABILITY_REQUIREMENT:
      return 'Availability Requirement';
    case EnvironmentalMetric.MODIFIED_ATTACK_VECTOR:
      return 'Modified Attack Vector';
    case EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY:
      return 'Modified Attack Complexity';
    case EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED:
      return 'Modified Privileges Required';
    case EnvironmentalMetric.MODIFIED_USER_INTERACTION:
      return 'Modified User Interaction';
    case EnvironmentalMetric.MODIFIED_SCOPE:
      return 'Modified Scope';
    case EnvironmentalMetric.MODIFIED_CONFIDENTIALITY:
      return 'Modified Confidentiality';
    case EnvironmentalMetric.MODIFIED_INTEGRITY:
      return 'Modified Integrity';
    case EnvironmentalMetric.MODIFIED_AVAILABILITY:
      return 'Modified Availability';
    default:
      return 'Unknown';
  }
};

// eslint-disable-next-line complexity
export const humanizeMetricValue = (
  value: MetricValue,
  metric: Metric
): string => {
  switch (metric) {
    case BaseMetric.ATTACK_VECTOR:
      switch (value) {
        case 'N':
          return 'Network';
        case 'A':
          return 'Adjacent';
        case 'L':
          return 'Local';
        case 'P':
          return 'Physical';
      }
      break;
    case BaseMetric.ATTACK_COMPLEXITY:
      switch (value) {
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
      }
      break;
    case BaseMetric.PRIVILEGES_REQUIRED:
      switch (value) {
        case 'N':
          return 'None';
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
      }
      break;
    case BaseMetric.USER_INTERACTION:
      switch (value) {
        case 'N':
          return 'None';
        case 'R':
          return 'Required';
      }
      break;
    case BaseMetric.SCOPE:
      switch (value) {
        case 'U':
          return 'Unchanged';
        case 'C':
          return 'Changed';
      }
      break;
    case BaseMetric.CONFIDENTIALITY:
    case BaseMetric.INTEGRITY:
    case BaseMetric.AVAILABILITY:
      switch (value) {
        case 'N':
          return 'None';
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
      }
      break;
    case TemporalMetric.EXPLOIT_CODE_MATURITY:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'U':
          return 'Unproven';
        case 'P':
          return 'Proof-of-Concept';
        case 'F':
          return 'Functional';
        case 'H':
          return 'High';
      }
      break;
    case TemporalMetric.REMEDIATION_LEVEL:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'O':
          return 'Official Fix';
        case 'T':
          return 'Temporary Fix';
        case 'W':
          return 'Workaround';
        case 'U':
          return 'Unavailable';
      }
      break;
    case TemporalMetric.REPORT_CONFIDENCE:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'U':
          return 'Unknown';
        case 'R':
          return 'Reasonable';
        case 'C':
          return 'Confirmed';
      }
      break;
    case EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT:
    case EnvironmentalMetric.INTEGRITY_REQUIREMENT:
    case EnvironmentalMetric.AVAILABILITY_REQUIREMENT:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'L':
          return 'Low';
        case 'M':
          return 'Medium';
        case 'H':
          return 'High';
      }
      break;
    case EnvironmentalMetric.MODIFIED_ATTACK_VECTOR:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'N':
          return 'Network';
        case 'A':
          return 'Adjacent Network';
        case 'L':
          return 'Local';
        case 'P':
          return 'Physical';
      }
      break;
    case EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
      }
      break;
    case EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'N':
          return 'None';
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
      }
      break;
    case EnvironmentalMetric.MODIFIED_USER_INTERACTION:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'N':
          return 'None';
        case 'R':
          return 'Required';
      }
      break;
    case EnvironmentalMetric.MODIFIED_SCOPE:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'U':
          return 'Unchanged';
        case 'C':
          return 'Changed';
      }
      break;
    case EnvironmentalMetric.MODIFIED_CONFIDENTIALITY:
    case EnvironmentalMetric.MODIFIED_INTEGRITY:
    case EnvironmentalMetric.MODIFIED_AVAILABILITY:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'N':
          return 'None';
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
      }
      break;
  }

  return 'Unknown';
};

// legacy, before introduction of Temporal and Environmental metrics support
export const humanizeBaseMetric = (metric: BaseMetric): string =>
  humanizeMetric(metric);

// legacy, before introduction of Temporal and Environmental metrics support
export const humanizeBaseMetricValue = (
  value: MetricValue,
  metric: BaseMetric
): string => humanizeMetricValue(value, metric);
