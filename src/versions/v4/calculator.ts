import { CvssCalculator } from '../../common/CvssCalculator';
import { CvssResult } from '../../common/CvssResult';
import { parseMetricsAsMap } from '../../parser';
import { cvssLookup } from './cvss-lookup';
import {
  baseMetrics,
  EnvironmentalMetric,
  Metric,
  MetricValue,
  ThreatMetric
} from './models';
import {
  MacroVector,
  getNeighborMacros,
  getMaxVectorsForMacro,
  getDistancesToMaxVector,
  getMaxMacroDistances
} from './macrovector';

export class CvssV4Calculator implements CvssCalculator {
  public calculate(cvssString: string): CvssResult {
    const metricsMap = parseMetricsAsMap(cvssString) as Map<
      Metric,
      MetricValue
    >;
    const baseScore = this.calculateScore(metricsMap);

    return {
      version: '4.0',
      baseScore,
      metrics: metricsMap
    };
  }

  private populateDefaults(
    metricsMap: Map<Metric, MetricValue>
  ): Map<Metric, MetricValue> {
    const result = new Map<Metric, MetricValue>(metricsMap);

    const exploitMaturity = ThreatMetric.EXPLOIT_MATURITY;
    if (!result.has(exploitMaturity) || result.get(exploitMaturity) === 'X') {
      result.set(exploitMaturity, 'A');
    }

    const confidentialityRequirement =
      EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT;
    if (
      !result.has(confidentialityRequirement) ||
      result.get(confidentialityRequirement) === 'X'
    ) {
      result.set(confidentialityRequirement, 'H');
    }

    const integrityRequirement = EnvironmentalMetric.INTEGRITY_REQUIREMENT;
    if (
      !result.has(integrityRequirement) ||
      result.get(integrityRequirement) === 'X'
    ) {
      result.set(integrityRequirement, 'H');
    }

    const availabilityRequirement =
      EnvironmentalMetric.AVAILABILITY_REQUIREMENT;
    if (
      !result.has(availabilityRequirement) ||
      result.get(availabilityRequirement) === 'X'
    ) {
      result.set(availabilityRequirement, 'H');
    }

    return result;
  }

  private getEffectiveMetricsMap(
    metricsMap: Map<Metric, MetricValue>
  ): Map<Metric, MetricValue> {
    const result = new Map<Metric, MetricValue>(metricsMap);
    for (const metric of baseMetrics) {
      const modifiedMetric = ('M' + metric) as Metric;
      const modifiedValue = metricsMap.get(modifiedMetric);
      if (modifiedValue && modifiedValue !== 'X') {
        result.set(metric, modifiedValue);
        continue;
      }
    }

    return result;
  }

  private calculateScore(metricsMap: Map<Metric, MetricValue>): number {
    const defaultedMap = this.populateDefaults(metricsMap);
    const effectiveMetrics = this.getEffectiveMetricsMap(defaultedMap);

    const finalScore = this.interpolateScore(
      new MacroVector(effectiveMetrics),
      effectiveMetrics
    );

    return Math.round(finalScore * 10) / 10;
  }

  private interpolateScore(
    macroVector: MacroVector,
    metrics: Map<Metric, MetricValue>
  ): number {
    const value = cvssLookup[macroVector.toString()];

    const nextLowerMacroVectors = getNeighborMacros(macroVector);
    const nextLowerMacroScores = nextLowerMacroVectors.map((macros) =>
      macros.length
        ? Math.max(0, ...macros.map((m) => cvssLookup[m]))
        : Number.NaN
    );
    const scoreDeltas = nextLowerMacroScores.map((score) => value - score);

    const metricDistances = getDistancesToMaxVector(
      metrics,
      getMaxVectorsForMacro(macroVector)
    );

    const currentMacroDistances = [
      metricDistances.AV + metricDistances.PR + metricDistances.UI,
      metricDistances.AC + metricDistances.AT,
      metricDistances.VC +
        metricDistances.VI +
        metricDistances.VA +
        metricDistances.CR +
        metricDistances.IR +
        metricDistances.AR,
      metricDistances.SC + metricDistances.SI + metricDistances.SA,
      0
    ];

    const maxMacroDistances = getMaxMacroDistances(macroVector);

    let lowerNeighborCounter = 0;
    const weightedDistances = [0, 0, 0, 0, 0];

    for (let i = 0; i < scoreDeltas.length; ++i) {
      const delta = scoreDeltas[i];
      const maxDistance = maxMacroDistances[i];
      if (isNaN(delta) || maxDistance <= 0) {
        continue;
      }

      lowerNeighborCounter += 1;
      if (i === 4) {
        weightedDistances[i] = 0;
        continue;
      }

      weightedDistances[i] = delta * (currentMacroDistances[i] / maxDistance);
    }

    let meanDistance = 0;
    if (lowerNeighborCounter !== 0) {
      const sum = weightedDistances.reduce((acc, ns) => acc + ns, 0);
      meanDistance = sum / lowerNeighborCounter;
    }

    return Math.max(0.0, Math.min(10.0, value - meanDistance));
  }
}
