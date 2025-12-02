import {
  type BaseMetric,
  type EnvironmentalMetric,
  type Metric,
  type MetricValue,
  type Metrics,
  type TemporalMetric,
  baseMetricValues,
  baseMetrics,
  environmentalMetricValues,
  environmentalMetrics,
  temporalMetricValues,
  temporalMetrics
} from './models';
import { parseMetricsAsMap, parseVector, parseVersion } from '../../parser';

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

const validateVector = (vectorStr: string | null): void => {
  if (!vectorStr || vectorStr.includes('//')) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C'
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
  metrics: ReadonlyArray<BaseMetric> = baseMetrics
): void => {
  metrics.forEach((metric: Metric) => {
    if (!metricsMap.has(metric)) {
      throw new Error(`Missing mandatory CVSS metric ${metric}`);
    }
  });
};

const checkMetricsValues = (
  metricsMap: Map<string, string>,
  metrics: Metrics,
  metricsValues: Record<Metric, MetricValue[]>
): void => {
  metrics.forEach((metric: Metric) => {
    const userValue = metricsMap.get(metric);
    if (!userValue) {
      return;
    }
    if (!metricsValues[metric].includes(userValue as MetricValue)) {
      const allowedValues = metricsValues[metric].join(', ');
      throw new Error(
        `Invalid value for CVSS metric ${metric}: ${userValue}. Allowed values: ${allowedValues}`
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
    metricsMap: metricsMap as Map<Metric, MetricValue>,
    isTemporal,
    isEnvironmental,
    versionStr
  };
};
