import { BaseMetric, BaseMetricValue } from './models';

export interface KeyValue<K, V> {
  key: K;
  value: V;
}

const versionRegex = /^CVSS:(\d(?:\.\d)?)(.*)?$/;

export const parseVersion = (cvssStr: string): string | null => {
  const versionRegexRes = versionRegex.exec(cvssStr);

  return versionRegexRes && versionRegexRes[1];
};

export const parseVector = (cvssStr: string): string | null => {
  const versionRegexRes = versionRegex.exec(cvssStr);

  return versionRegexRes && versionRegexRes[2] && versionRegexRes[2].substr(1);
};

export const parseMetrics = (vectorStr: string): KeyValue<string, string>[] =>
  vectorStr.split('/').map((metric: string) => {
    if (!metric) {
      return { key: '', value: '' };
    }

    const parts = metric.split(':');

    return { key: parts[0], value: parts[1] };
  });

export const parseMetricsAsMap = (
  cvssStr: string
): Map<BaseMetric, BaseMetricValue> =>
  parseMetrics(parseVector(cvssStr) as string).reduce(
    (
      res: Map<BaseMetric, BaseMetricValue>,
      metric: KeyValue<string, string>
    ): Map<BaseMetric, BaseMetricValue> => {
      if (res.has(metric.key as BaseMetric)) {
        throw new Error(
          `Duplicated metric: "${metric.key}:${metric.value || ''}"`
        );
      }

      res.set(metric.key as BaseMetric, metric.value as BaseMetricValue);

      return res;
    },
    new Map<BaseMetric, BaseMetricValue>()
  );
