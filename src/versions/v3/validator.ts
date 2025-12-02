import {
  baseMetricValues,
  baseMetrics,
  environmentalMetricValues,
  environmentalMetrics,
  temporalMetricValues,
  temporalMetrics
} from './models';
import { humanizeMetric, humanizeMetricValue } from './humanizer';
import { validateByKnownMaps } from '../validator';

export const validateVersion = (versionStr: string | null): void => {
  if (!versionStr) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L'
    );
  }

  if (versionStr !== '3.0' && versionStr !== '3.1') {
    throw new Error(
      `Unsupported CVSS version: ${versionStr}. Only 3.0 and 3.1 are supported by this validator.`
    );
  }
};

export const validate = (cvssStr: string) =>
  validateByKnownMaps(
    cvssStr,
    validateVersion,
    {
      base: baseMetrics,
      temporal: temporalMetrics,
      environmental: environmentalMetrics
    },
    {
      ...baseMetricValues,
      ...temporalMetricValues,
      ...environmentalMetricValues
    },
    {
      humanizeMetric,
      humanizeMetricValue
    }
  );
