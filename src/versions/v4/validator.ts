import {
  baseMetricValues,
  baseMetrics,
  environmentalMetricValues,
  environmentalMetrics,
  threatMetricValues,
  threatMetrics,
  supplementalMetricValues,
  supplementalMetrics
} from './models';
import { validateByKnownMaps } from '../validator';

export const validateVersion = (versionStr: string | null): void => {
  if (!versionStr) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'
    );
  }

  if (versionStr !== '4.0') {
    throw new Error(
      `Unsupported CVSS version: ${versionStr}. Only 4.0 is supported by this validator.`
    );
  }
};

export const validate = (cvssStr: string) =>
  validateByKnownMaps(
    cvssStr,
    validateVersion,
    {
      base: baseMetrics,
      threat: threatMetrics,
      environmental: environmentalMetrics,
      supplemental: supplementalMetrics
    },
    {
      ...baseMetricValues,
      ...threatMetricValues,
      ...environmentalMetricValues,
      ...supplementalMetricValues
    }
  );
