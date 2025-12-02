import {
  BaseMetric,
  BaseMetricValue,
  EnvironmentalMetric,
  EnvironmentalMetricValue,
  Metric,
  MetricValue,
  TemporalMetric,
  TemporalMetricValue,
  environmentalMetrics,
  temporalMetrics
} from './models';
import { validate } from './validator';
import { CvssCalculator } from '../../common/CvssCalculator';
import { CvssResultV2 } from '../../common/CvssResult';

const baseMetricValueScores: Record<
  BaseMetric,
  Partial<Record<BaseMetricValue, number>>
> = {
  [BaseMetric.ACCESS_VECTOR]: { L: 0.395, A: 0.646, N: 1.0 },
  [BaseMetric.ACCESS_COMPLEXITY]: { H: 0.35, M: 0.61, L: 0.71 },
  [BaseMetric.AUTHENTICATION]: { M: 0.45, S: 0.56, N: 0.704 },
  [BaseMetric.CONFIDENTIALITY_IMPACT]: { N: 0, P: 0.275, C: 0.66 },
  [BaseMetric.INTEGRITY_IMPACT]: { N: 0, P: 0.275, C: 0.66 },
  [BaseMetric.AVAILABILITY_IMPACT]: { N: 0, P: 0.275, C: 0.66 }
};

const temporalMetricValueScores: Record<
  TemporalMetric,
  Partial<Record<TemporalMetricValue, number>>
> = {
  [TemporalMetric.EXPLOITABILITY]: {
    ND: 1.0,
    U: 0.85,
    POC: 0.9,
    F: 0.95,
    H: 1.0
  },
  [TemporalMetric.REMEDIATION_LEVEL]: {
    ND: 1.0,
    OF: 0.87,
    TF: 0.9,
    W: 0.95,
    U: 1.0
  },
  [TemporalMetric.REPORT_CONFIDENCE]: {
    ND: 1.0,
    UC: 0.9,
    UR: 0.95,
    C: 1.0
  }
};

const environmentalMetricValueScores: Record<
  EnvironmentalMetric,
  Partial<Record<EnvironmentalMetricValue, number>>
> = {
  [EnvironmentalMetric.COLLATERAL_DAMAGE_POTENTIAL]: {
    ND: 0,
    N: 0,
    L: 0.1,
    LM: 0.3,
    MH: 0.4,
    H: 0.5
  },
  [EnvironmentalMetric.TARGET_DISTRIBUTION]: {
    ND: 1.0,
    N: 0,
    L: 0.25,
    M: 0.75,
    H: 1.0
  },
  [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: {
    ND: 1.0,
    L: 0.5,
    M: 1.0,
    H: 1.51
  },
  [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: {
    ND: 1.0,
    L: 0.5,
    M: 1.0,
    H: 1.51
  },
  [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: {
    ND: 1.0,
    L: 0.5,
    M: 1.0,
    H: 1.51
  }
};

const getMetricNumericValue = (
  metric: Metric,
  metricsMap: Map<Metric, MetricValue>
): number => {
  if (!metricsMap.has(metric)) {
    throw new Error(`Missing metric: ${metric}`);
  }

  const score: Partial<Record<MetricValue, number>> | null = {
    ...baseMetricValueScores,
    ...temporalMetricValueScores,
    ...environmentalMetricValueScores
  }[metric];

  if (!score) {
    throw new Error(`Internal error. Missing metric score: ${metric}`);
  }

  return score[metricsMap.get(metric)!]!;
};

const round = (input: number): number => Math.round(input * 10) / 10;

export const populateTemporalMetricDefaults = (
  metricsMap: Map<Metric, MetricValue>
): Map<Metric, MetricValue> => {
  [...temporalMetrics].forEach((metric) => {
    if (!metricsMap.has(metric)) {
      metricsMap.set(metric, 'ND');
    }
  });

  return metricsMap;
};

export const populateEnvironmentalMetricDefaults = (
  metricsMap: Map<Metric, MetricValue>
): Map<Metric, MetricValue> => {
  [...environmentalMetrics].forEach((metric) => {
    if (!metricsMap.has(metric)) {
      metricsMap.set(metric, 'ND');
    }
  });

  return metricsMap;
};

export class CvssV2Calculator implements CvssCalculator {
  public calculate(cvssString: string): CvssResultV2 {
    const { metricsMap } = validate(cvssString);

    const baseResult = this.calculateBaseScore(metricsMap);
    const temporalResult = this.calculateTemporalScore(baseResult, metricsMap);
    const environmentalResult = this.calculateEnvironmentalScore(
      baseResult,
      metricsMap
    );

    return {
      ...baseResult,
      ...temporalResult,
      ...environmentalResult,
      version: '2.0',
      metrics: metricsMap as Map<string, string>
    };
  }

  private calculateBaseScore(
    metricsMap: Map<Metric, MetricValue>
  ): Pick<CvssResultV2, 'baseScore' | 'baseImpact' | 'baseExploitability'> {
    const impact = this.calculateImpact(metricsMap);
    const exploitability = this.calculateExploitability(metricsMap);

    const fImpact = impact === 0 ? 0 : 1.176;
    const baseScore = (0.6 * impact + 0.4 * exploitability - 1.5) * fImpact;

    return {
      baseScore: round(baseScore),
      baseImpact: round(impact),
      baseExploitability: round(exploitability)
    };
  }

  private calculateImpact(metricsMap: Map<Metric, MetricValue>): number {
    const c = getMetricNumericValue(
      BaseMetric.CONFIDENTIALITY_IMPACT,
      metricsMap
    );
    const i = getMetricNumericValue(BaseMetric.INTEGRITY_IMPACT, metricsMap);
    const a = getMetricNumericValue(BaseMetric.AVAILABILITY_IMPACT, metricsMap);

    return 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
  }

  private calculateExploitability(
    metricsMap: Map<Metric, MetricValue>
  ): number {
    const av = getMetricNumericValue(BaseMetric.ACCESS_VECTOR, metricsMap);
    const ac = getMetricNumericValue(BaseMetric.ACCESS_COMPLEXITY, metricsMap);
    const au = getMetricNumericValue(BaseMetric.AUTHENTICATION, metricsMap);

    return 20 * av * ac * au;
  }

  private calculateTemporalScore(
    baseResult: Pick<CvssResultV2, 'baseScore'>,
    metricsMap: Map<Metric, MetricValue>
  ): Pick<CvssResultV2, 'temporalScore'> {
    populateTemporalMetricDefaults(metricsMap);

    const e = getMetricNumericValue(TemporalMetric.EXPLOITABILITY, metricsMap);
    const rl = getMetricNumericValue(
      TemporalMetric.REMEDIATION_LEVEL,
      metricsMap
    );
    const rc = getMetricNumericValue(
      TemporalMetric.REPORT_CONFIDENCE,
      metricsMap
    );

    const temporalScore = round(baseResult.baseScore * e * rl * rc);

    return { temporalScore };
  }

  private calculateEnvironmentalScore(
    baseResult: Pick<CvssResultV2, 'baseScore' | 'baseExploitability'>,
    metricsMap: Map<Metric, MetricValue>
  ): Pick<CvssResultV2, 'environmentalScore'> {
    populateEnvironmentalMetricDefaults(metricsMap);

    const cdp = getMetricNumericValue(
      EnvironmentalMetric.COLLATERAL_DAMAGE_POTENTIAL,
      metricsMap
    );
    const td = getMetricNumericValue(
      EnvironmentalMetric.TARGET_DISTRIBUTION,
      metricsMap
    );

    // Adjusted Impact
    const c = getMetricNumericValue(
      BaseMetric.CONFIDENTIALITY_IMPACT,
      metricsMap
    );
    const i = getMetricNumericValue(BaseMetric.INTEGRITY_IMPACT, metricsMap);
    const a = getMetricNumericValue(BaseMetric.AVAILABILITY_IMPACT, metricsMap);
    const cr = getMetricNumericValue(
      EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
      metricsMap
    );
    const ir = getMetricNumericValue(
      EnvironmentalMetric.INTEGRITY_REQUIREMENT,
      metricsMap
    );
    const ar = getMetricNumericValue(
      EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
      metricsMap
    );
    const adjustedImpact = Math.min(
      10,
      10.41 * (1 - (1 - c * cr) * (1 - i * ir) * (1 - a * ar))
    );

    // Adjusted Base
    const fImpact = adjustedImpact === 0 ? 0 : 1.176;
    const adjustedBase = round(
      (0.6 * adjustedImpact + 0.4 * baseResult.baseExploitability - 1.5) *
        fImpact
    );

    // Adjusted Temporal
    const e = getMetricNumericValue(TemporalMetric.EXPLOITABILITY, metricsMap);
    const rl = getMetricNumericValue(
      TemporalMetric.REMEDIATION_LEVEL,
      metricsMap
    );
    const rc = getMetricNumericValue(
      TemporalMetric.REPORT_CONFIDENCE,
      metricsMap
    );
    const adjustedTemporal = round(adjustedBase * e * rl * rc);
    const environmentalScore = round(
      (adjustedTemporal + (10 - adjustedTemporal) * cdp) * td
    );

    return { environmentalScore };
  }
}
