import {
  baseMetricValues,
  baseMetrics,
  environmentalMetricValues,
  environmentalMetrics,
  temporalMetricValues,
  temporalMetrics
} from './models';
import { validateByKnownMaps } from '../validator';
import { humanizeMetric, humanizeMetricValue } from './humanizer';

export const validateVersion = (versionStr: string | null): void => {
  if (!versionStr) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C'
    );
  }

  if (versionStr !== '2.0') {
    throw new Error(
      `Unsupported CVSS version: ${versionStr}. Only 2.0 is supported by this validator.`
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
