export interface KeyValue<K, V> {
  key: K;
  value: V;
}

const VERSION_REGEX = /^CVSS:(\d(?:\.\d)?)(.*)?$/;

export const parseVersion = (cvssStr: string): string | null => {
  const versionRegexRes = VERSION_REGEX.exec(cvssStr);

  return versionRegexRes && versionRegexRes[1];
};

export const parseVector = (cvssStr: string): string | null => {
  const versionRegexRes = VERSION_REGEX.exec(cvssStr);

  return (
    versionRegexRes && versionRegexRes[2] && versionRegexRes[2].substring(1)
  );
};

export const parseMetrics = (vectorStr: string): KeyValue<string, string>[] =>
  (vectorStr ? vectorStr.split('/') : []).map((metric: string) => {
    if (!metric) {
      return { key: '', value: '' };
    }

    const parts = metric.split(':');

    return { key: parts[0], value: parts[1] };
  });

export const parseMetricsAsMap = (cvssStr: string): Map<string, string> =>
  parseMetrics(parseVector(cvssStr) || '').reduce(
    (
      res: Map<string, string>,
      metric: KeyValue<string, string>
    ): Map<string, string> => {
      if (res.has(metric.key)) {
        throw new Error(
          `Duplicated metric: "${metric.key}:${metric.value || ''}"`
        );
      }

      return res.set(metric.key, metric.value);
    },
    new Map<string, string>()
  );
