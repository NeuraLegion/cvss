import {
  BaseMetric,
  EnvironmentalMetric,
  Metric,
  MetricValue,
  TemporalMetric
} from './models';

// eslint-disable-next-line complexity
export const humanizeMetric = (metric: string): string => {
  switch (metric) {
    case BaseMetric.ACCESS_VECTOR:
      return 'Access Vector';
    case BaseMetric.ACCESS_COMPLEXITY:
      return 'Access Complexity';
    case BaseMetric.AUTHENTICATION:
      return 'Authentication';
    case BaseMetric.CONFIDENTIALITY_IMPACT:
      return 'Confidentiality Impact';
    case BaseMetric.INTEGRITY_IMPACT:
      return 'Integrity Impact';
    case BaseMetric.AVAILABILITY_IMPACT:
      return 'Availability Impact';
    case TemporalMetric.EXPLOITABILITY:
      return 'Exploitability';
    case TemporalMetric.REMEDIATION_LEVEL:
      return 'Remediation Level';
    case TemporalMetric.REPORT_CONFIDENCE:
      return 'Report Confidence';
    case EnvironmentalMetric.COLLATERAL_DAMAGE_POTENTIAL:
      return 'Collateral Damage Potential';
    case EnvironmentalMetric.TARGET_DISTRIBUTION:
      return 'Target Distribution';
    case EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT:
      return 'Confidentiality Requirement';
    case EnvironmentalMetric.INTEGRITY_REQUIREMENT:
      return 'Integrity Requirement';
    case EnvironmentalMetric.AVAILABILITY_REQUIREMENT:
      return 'Availability Requirement';
    default:
      return 'Unknown';
  }
};

// eslint-disable-next-line complexity
export const humanizeMetricValue = (value: string, metric: string): string => {
  switch (metric) {
    case BaseMetric.ACCESS_VECTOR:
      switch (value) {
        case 'L':
          return 'Local';
        case 'A':
          return 'Adjacent Network';
        case 'N':
          return 'Network';
      }
      break;
    case BaseMetric.ACCESS_COMPLEXITY:
      switch (value) {
        case 'H':
          return 'High';
        case 'M':
          return 'Medium';
        case 'L':
          return 'Low';
      }
      break;
    case BaseMetric.AUTHENTICATION:
      switch (value) {
        case 'M':
          return 'Multiple';
        case 'S':
          return 'Single';
        case 'N':
          return 'None';
      }
      break;
    case BaseMetric.CONFIDENTIALITY_IMPACT:
    case BaseMetric.INTEGRITY_IMPACT:
    case BaseMetric.AVAILABILITY_IMPACT:
      switch (value) {
        case 'N':
          return 'None';
        case 'P':
          return 'Partial';
        case 'C':
          return 'Complete';
      }
      break;
    case TemporalMetric.EXPLOITABILITY:
      switch (value) {
        case 'U':
          return 'Unproven that exploit exists';
        case 'POC':
          return 'Proof of concept code';
        case 'F':
          return 'Functional exploit exists';
        case 'H':
          return 'High';
        case 'ND':
          return 'Not Defined';
      }
      break;
    case TemporalMetric.REMEDIATION_LEVEL:
      switch (value) {
        case 'OF':
          return 'Official fix';
        case 'TF':
          return 'Temporary fix';
        case 'W':
          return 'Workaround';
        case 'U':
          return 'Unavailable';
        case 'ND':
          return 'Not Defined';
      }
      break;
    case TemporalMetric.REPORT_CONFIDENCE:
      switch (value) {
        case 'UC':
          return 'Unconfirmed';
        case 'UR':
          return 'Uncorroborated';
        case 'C':
          return 'Confirmed';
        case 'ND':
          return 'Not Defined';
      }
      break;
    case EnvironmentalMetric.COLLATERAL_DAMAGE_POTENTIAL:
      switch (value) {
        case 'N':
          return 'None';
        case 'L':
          return 'Low (light loss)';
        case 'LM':
          return 'Low-Medium';
        case 'MH':
          return 'Medium-High';
        case 'H':
          return 'High (catastrophic loss)';
        case 'ND':
          return 'Not Defined';
      }
      break;
    case EnvironmentalMetric.TARGET_DISTRIBUTION:
      switch (value) {
        case 'N':
          return 'None [0%]';
        case 'L':
          return 'Low [0-25%]';
        case 'M':
          return 'Medium [26-75%]';
        case 'H':
          return 'High [76-100%]';
        case 'ND':
          return 'Not Defined';
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
        case 'ND':
          return 'Not Defined';
      }
      break;
  }

  return 'Unknown';
};

// legacy, before introduction of Temporal and Environmental metrics support
export const humanizeBaseMetric = (metric: Metric): string =>
  humanizeMetric(metric);

// legacy, before introduction of Temporal and Environmental metrics support
export const humanizeBaseMetricValue = (
  value: Metric,
  metric: MetricValue
): string => humanizeMetricValue(value, metric);
