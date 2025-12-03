import {
  BaseMetric,
  EnvironmentalMetric,
  Metric,
  MetricValue,
  SupplementalMetric,
  ThreatMetric
} from './models';

// eslint-disable-next-line complexity
export const humanizeMetric = (metric: Metric): string => {
  switch (metric) {
    case BaseMetric.ATTACK_VECTOR:
      return 'Attack Vector';
    case BaseMetric.ATTACK_COMPLEXITY:
      return 'Attack Complexity';
    case BaseMetric.ATTACK_REQUIREMENTS:
      return 'Attack Requirements';
    case BaseMetric.PRIVILEGES_REQUIRED:
      return 'Privileges Required';
    case BaseMetric.USER_INTERACTION:
      return 'User Interaction';
    case BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY:
      return 'Vulnerable System Confidentiality';
    case BaseMetric.VULNERABLE_SYSTEM_INTEGRITY:
      return 'Vulnerable System Integrity';
    case BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY:
      return 'Vulnerable System Availability';
    case BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY:
      return 'Subsequent System Confidentiality';
    case BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY:
      return 'Subsequent System Integrity';
    case BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY:
      return 'Subsequent System Availability';
    case ThreatMetric.EXPLOIT_MATURITY:
      return 'Exploit Maturity';
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
    case EnvironmentalMetric.MODIFIED_ATTACK_REQUIREMENTS:
      return 'Modified Attack Requirements';
    case EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED:
      return 'Modified Privileges Required';
    case EnvironmentalMetric.MODIFIED_USER_INTERACTION:
      return 'Modified User Interaction';
    case EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_CONFIDENTIALITY:
      return 'Modified Vulnerable System Confidentiality';
    case EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_INTEGRITY:
      return 'Modified Vulnerable System Integrity';
    case EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_AVAILABILITY:
      return 'Modified Vulnerable System Availability';
    case EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_CONFIDENTIALITY:
      return 'Modified Subsequent System Confidentiality';
    case EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_INTEGRITY:
      return 'Modified Subsequent System Integrity';
    case EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_AVAILABILITY:
      return 'Modified Subsequent System Availability';
    case SupplementalMetric.SAFETY:
      return 'Safety';
    case SupplementalMetric.AUTOMATABLE:
      return 'Automatable';
    case SupplementalMetric.RECOVERY:
      return 'Recovery';
    case SupplementalMetric.VALUE_DENSITY:
      return 'Value Density';
    case SupplementalMetric.VULNERABILITY_RESPONSE_EFFORT:
      return 'Vulnerability Response Effort';
    case SupplementalMetric.PROVIDER_URGENCY:
      return 'Provider Urgency';
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
    case EnvironmentalMetric.MODIFIED_ATTACK_VECTOR:
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
    case EnvironmentalMetric.MODIFIED_ATTACK_COMPLEXITY:
      switch (value) {
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
      }
      break;
    case BaseMetric.ATTACK_REQUIREMENTS:
    case EnvironmentalMetric.MODIFIED_ATTACK_REQUIREMENTS:
      switch (value) {
        case 'N':
          return 'None';
        case 'P':
          return 'Present';
      }
      break;
    case BaseMetric.PRIVILEGES_REQUIRED:
    case EnvironmentalMetric.MODIFIED_PRIVILEGES_REQUIRED:
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
    case EnvironmentalMetric.MODIFIED_USER_INTERACTION:
      switch (value) {
        case 'N':
          return 'None';
        case 'P':
          return 'Passive';
        case 'A':
          return 'Active';
      }
      break;
    case BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY:
    case BaseMetric.VULNERABLE_SYSTEM_INTEGRITY:
    case BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY:
    case BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY:
    case BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY:
    case BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY:
    case EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_CONFIDENTIALITY:
    case EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_INTEGRITY:
    case EnvironmentalMetric.MODIFIED_VULNERABLE_SYSTEM_AVAILABILITY:
    case EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_CONFIDENTIALITY:
    case EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_INTEGRITY:
    case EnvironmentalMetric.MODIFIED_SUBSEQUENT_SYSTEM_AVAILABILITY:
      switch (value) {
        case 'N':
          return 'None';
        case 'L':
          return 'Low';
        case 'H':
          return 'High';
        case 'S':
          return 'Safety';
      }
      break;
    case ThreatMetric.EXPLOIT_MATURITY:
      switch (value) {
        case 'U':
          return 'Unreported';
        case 'P':
          return 'Proof-of-Concept';
        case 'A':
          return 'Attacked';
      }
      break;
    case EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT:
    case EnvironmentalMetric.INTEGRITY_REQUIREMENT:
    case EnvironmentalMetric.AVAILABILITY_REQUIREMENT:
      switch (value) {
        case 'L':
          return 'Low';
        case 'M':
          return 'Medium';
        case 'H':
          return 'High';
      }
      break;
    case SupplementalMetric.SAFETY:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'N':
          return 'Negligible';
        case 'P':
          return 'Present';
      }
      break;
    case SupplementalMetric.AUTOMATABLE:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'N':
          return 'No';
        case 'Y':
          return 'Yes';
      }
      break;
    case SupplementalMetric.RECOVERY:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'A':
          return 'Automatic';
        case 'U':
          return 'User';
        case 'I':
          return 'Irrecoverable';
      }
      break;
    case SupplementalMetric.VALUE_DENSITY:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'D':
          return 'Diffuse';
        case 'C':
          return 'Concentrated';
      }
      break;
    case SupplementalMetric.VULNERABILITY_RESPONSE_EFFORT:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'L':
          return 'Low';
        case 'M':
          return 'Moderate';
        case 'H':
          return 'High';
      }
      break;
    case SupplementalMetric.PROVIDER_URGENCY:
      switch (value) {
        case 'X':
          return 'Not Defined';
        case 'R':
          return 'Red';
        case 'A':
          return 'Amber';
        case 'G':
          return 'Green';
        case 'C':
          return 'Clear';
      }
      break;
  }

  if (value === 'X') {
    return 'Not Defined';
  }

  return 'Unknown';
};
