import { parseMetricsAsMap, parseVector, parseVersion } from '../parser';

interface Humanizer {
  humanizeMetric(metric: string): string;
  humanizeMetricValue(value: string, metric: string): string;
}

type ValidationResult = {
  isTemporal: boolean;
  isEnvironmental: boolean;
  metricsMap: Map<string, string>;
  versionStr: string | null;
};

const validateVector = (vectorStr: string | null): void => {
  if (!vectorStr || vectorStr.includes('//')) {
    throw new Error('Invalid CVSS string');
  }
};

const checkUnknownMetrics = (
  metricsMap: Map<string, string>,
  knownMetrics: ReadonlyArray<string>
): void => {
  [...metricsMap.keys()].forEach((userMetric: string) => {
    if (!knownMetrics.includes(userMetric)) {
      throw new Error(
        `Unknown CVSS metric "${userMetric}". Allowed metrics: ${knownMetrics.join(
          ', '
        )}`
      );
    }
  });
};

const checkMandatoryMetrics = (
  metricsMap: Map<string, string>,
  metrics: ReadonlyArray<string>,
  humanizer?: Humanizer
): void => {
  metrics.forEach((metric: string) => {
    if (!metricsMap.has(metric)) {
      const metricName = humanizer ? humanizer.humanizeMetric(metric) : metric;
      throw new Error(`Missing mandatory CVSS metric ${metricName}`);
    }
  });
};

const checkMetricsValues = (
  metricsMap: Map<string, string>,
  metrics: ReadonlyArray<string>,
  metricsValues: Record<string, string[]>,
  humanizer?: Humanizer
): void => {
  metrics.forEach((metric: string) => {
    const userValue = metricsMap.get(metric);
    if (!userValue) {
      return;
    }
    if (!metricsValues[metric].includes(userValue)) {
      let errorMsg = '';
      if (humanizer) {
        const allowedValuesHumanized = metricsValues[metric]
          .map(
            (value) =>
              `${value} (${humanizer.humanizeMetricValue(value, metric)})`
          )
          .join(', ');
        errorMsg = `Invalid value for CVSS metric ${metric} (${humanizer.humanizeMetric(
          metric
        )})${
          userValue ? `: ${userValue}` : ''
        }. Allowed values: ${allowedValuesHumanized}`;
      } else {
        const allowedValues = metricsValues[metric].join(', ');
        errorMsg = `Invalid value for CVSS metric ${metric}: ${userValue}. Allowed values: ${allowedValues}`;
      }
      throw new Error(errorMsg);
    }
  });
};

export const validateByKnownMaps = (
  cvssStr: string,
  validateVersion: (versionStr: string | null) => void,
  metrics: Record<string, ReadonlyArray<string>>,
  knownMetricsValues: Record<string, string[]>,
  humanizer?: Humanizer
): ValidationResult => {
  if (!cvssStr || !cvssStr.startsWith('CVSS:')) {
    throw new Error('CVSS vector must start with "CVSS:"');
  }

  const versionStr = parseVersion(cvssStr);
  validateVersion(versionStr);

  const vectorStr = parseVector(cvssStr);
  validateVector(vectorStr);

  const knownMetrics = Object.values(metrics).flat();

  const metricsMap = parseMetricsAsMap(cvssStr);
  checkMandatoryMetrics(metricsMap, metrics.base, humanizer);
  checkUnknownMetrics(metricsMap, knownMetrics);
  checkMetricsValues(metricsMap, knownMetrics, knownMetricsValues, humanizer);

  const isTemporal =
    !!metrics.temporal &&
    [...metricsMap.keys()].some((metric) => metrics.temporal.includes(metric));
  const isEnvironmental =
    !!metrics.environmental &&
    [...metricsMap.keys()].some((metric) =>
      metrics.environmental.includes(metric)
    );

  return {
    metricsMap,
    isTemporal,
    isEnvironmental,
    versionStr
  };
};
