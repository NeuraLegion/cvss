import {
  Metric,
  MetricValue,
  Metrics,
  baseMetrics,
  temporalMetrics,
  environmentalMetrics,
  AllMetricValues,
  baseMetricValues,
  temporalMetricValues,
  environmentalMetricValues,
  TemporalMetric,
  EnvironmentalMetric
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

const checkUnknownMetrics = (
  metricsMap: Map<string, string>,
  knownMetrics?: Metrics
): void => {
  const allKnownMetrics = knownMetrics || [
    ...baseMetrics,
    ...temporalMetrics,
    ...environmentalMetrics
  ];

  [...metricsMap.keys()].forEach((userMetric: string) => {
    if (!allKnownMetrics.includes(userMetric as Metric)) {
      throw new Error(
        `Unknown CVSS metric "${userMetric}". Allowed metrics: ${allKnownMetrics.join(
          ', '
        )}`
      );
    }
  });
};

const checkMandatoryMetrics = (
  metricsMap: Map<string, string>,
  metrics: Metrics = baseMetrics
): void => {
  metrics.forEach((metric: Metric) => {
    if (!metricsMap.has(metric)) {
      // eslint-disable-next-line max-len
      throw new Error(
        `Missing mandatory CVSS metric ${metrics} (${humanizeBaseMetric(
          metric
        )})`
      );
    }
  });
};

const checkMetricsValues = (
  metricsMap: Map<string, string>,
  metrics: Metrics,
  metricsValues: AllMetricValues
): void => {
  metrics.forEach((metric: Metric) => {
    const userValue = metricsMap.get(metric);
    if (!userValue) {
      return;
    }
    if (!metricsValues[metric].includes(userValue as MetricValue)) {
      const allowedValuesHumanized = metricsValues[metric]
        .map(
          (value: MetricValue) =>
            `${value} (${humanizeBaseMetricValue(value, metric)})`
        )
        .join(', ');
      throw new Error(
        `Invalid value for CVSS metric ${metric} (${humanizeBaseMetric(
          metric
        )})${
          userValue ? `: ${userValue}` : ''
        }. Allowed values: ${allowedValuesHumanized}`
      );
    }
  });
};

type ValidationResult = {
  isTemporal: boolean;
  isEnvironmental: boolean;
  metricsMap: Map<Metric, MetricValue>;
  versionStr: string | null;
};

/**
 * Validate that the given string is a valid cvss vector
 * @param cvssStr
 */
export const validate = (cvssStr: string): ValidationResult => {
  if (!cvssStr || !cvssStr.startsWith('CVSS:')) {
    throw new Error('CVSS vector must start with "CVSS:"');
  }
  const allKnownMetrics = [
    ...baseMetrics,
    ...temporalMetrics,
    ...environmentalMetrics
  ];
  const allKnownMetricsValues = {
    ...baseMetricValues,
    ...temporalMetricValues,
    ...environmentalMetricValues
  };

  const versionStr = parseVersion(cvssStr);
  validateVersion(versionStr);

  const vectorStr = parseVector(cvssStr);
  validateVector(vectorStr);

  const metricsMap = parseMetricsAsMap(cvssStr);
  checkMandatoryMetrics(metricsMap);
  checkUnknownMetrics(metricsMap, allKnownMetrics);
  checkMetricsValues(metricsMap, allKnownMetrics, allKnownMetricsValues);

  const isTemporal = [...metricsMap.keys()].some((metric) =>
    temporalMetrics.includes(metric as TemporalMetric)
  );
  const isEnvironmental = [...metricsMap.keys()].some((metric) =>
    environmentalMetrics.includes(metric as EnvironmentalMetric)
  );

  return {
    metricsMap,
    isTemporal,
    isEnvironmental,
    versionStr
  };
};
