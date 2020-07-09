import {
  BaseMetric,
  baseMetrics,
  BaseMetricValue,
  baseMetricValues
} from './models';
import { humanizeBaseMetric, humanizeBaseMetricValue } from './humanizer';
import { parseMetricsAsMap, parseVector, parseVersion } from './parser';

export const validateVersion = (versionStr: string | null): void => {
  if (!versionStr) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L'
    );
  }

  if (versionStr !== '3.0' && versionStr !== '3.1') {
    throw new Error(
      `Unsupported CVSS version: ${versionStr}. Only 3.0 and 3.1 are supported`
    );
  }
};

const validateVector = (vectorStr: string | null): void => {
  if (!vectorStr || vectorStr.includes('//')) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L'
    );
  }
};

const checkUnknownBaseMetrics = (metricsMap: Map<string, string>): void => {
  [...metricsMap.keys()].forEach((userMetric: string) => {
    if (!baseMetrics.includes(userMetric as BaseMetric)) {
      throw new Error(
        `Unknown CVSS metric "${userMetric}". Allowed metrics: ${baseMetrics.join(
          ', '
        )}`
      );
    }
  });
};

const checkMandatoryBaseMetrics = (metricsMap: Map<string, string>): void => {
  baseMetrics.forEach((baseMetric: BaseMetric) => {
    if (!metricsMap.has(baseMetric)) {
      // eslint-disable-next-line max-len
      throw new Error(
        `Missing mandatory CVSS base metric ${baseMetric} (${humanizeBaseMetric(
          baseMetric
        )})`
      );
    }
  });
};

const checkBaseMetricsValues = (metricsMap: Map<string, string>): void => {
  baseMetrics.forEach((baseMetric: BaseMetric) => {
    const userValue = metricsMap.get(baseMetric);
    if (!baseMetricValues[baseMetric].includes(userValue as BaseMetricValue)) {
      const allowedValuesHumanized = baseMetricValues[baseMetric]
        .map(
          (value: BaseMetricValue) =>
            `${value} (${humanizeBaseMetricValue(value, baseMetric)})`
        )
        .join(', ');
      // eslint-disable-next-line max-len
      throw new Error(
        `Invalid value for CVSS metric ${baseMetric} (${humanizeBaseMetric(
          baseMetric
        )})${
          userValue ? `: ${userValue}` : ''
        }. Allowed values: ${allowedValuesHumanized}`
      );
    }
  });
};

export const validate = (cvssStr: string): void => {
  if (!cvssStr || !cvssStr.startsWith('CVSS:')) {
    throw new Error('CVSS vector must start with "CVSS:"');
  }

  const versionStr = parseVersion(cvssStr);
  validateVersion(versionStr);

  const vectorStr = parseVector(cvssStr);
  validateVector(vectorStr);

  const metricsMap: Map<string, string> = parseMetricsAsMap(cvssStr);
  checkUnknownBaseMetrics(metricsMap);
  checkMandatoryBaseMetrics(metricsMap);
  checkBaseMetricsValues(metricsMap);
};
