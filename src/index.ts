import type { CvssResult } from './common/CvssResult';
import type { CvssVersion } from './common/CvssVersion';
import { createCvssCalculator } from './factory';
import { Metric, MetricValue } from './versions/v3/models';
import { validate as validateV2 } from './versions/v2/validator';
import { validate as validateV3 } from './versions/v3/validator';
import { parseMetricsAsMap as parseMetricsAsMapString } from './parser';
import { parseVersion } from './parser';

// ============================================================================
// Backward Compatible Public API
// ============================================================================

export interface ScoreResult {
  score: number;
  impact: number;
  exploitability: number;
  metricsMap: Map<string, string>;
}

export const validate = (cvssString: string): void => {
  if (!cvssString || !cvssString.startsWith('CVSS:')) {
    throw new Error('CVSS vector must start with "CVSS:"');
  }

  const versionStr = parseVersion(cvssString);
  const validateString = versionStr === '2.0' ? validateV2 : validateV3;
  validateString(cvssString);
};

function calculateCvss(cvssString: string): CvssResult {
  const version = parseVersion(cvssString);
  if (!version) {
    throw new Error('Invalid CVSS string: unable to detect version');
  }

  validate(cvssString);

  return createCvssCalculator(version as CvssVersion).calculate(cvssString);
}

/**
 * Calculate the base score for a CVSS string
 * @param cvssString - The CVSS vector string
 * @returns The base score (0-10)
 */
export const calculateBaseScore = (cvssString: string): number =>
  calculateCvss(cvssString).baseScore;

/**
 * Calculate the temporal score for a CVSS string
 * @param cvssString - The CVSS vector string
 * @returns The temporal score (0-10)
 */
export const calculateTemporalScore = (cvssString: string): number => {
  const res = calculateCvss(cvssString);

  return res.temporalScore ?? res.baseScore;
};

/**
 * Calculate the environmental score for a CVSS string
 * @param cvssString - The CVSS vector string
 * @returns The environmental score (0-10)
 */
export const calculateEnvironmentalScore = (cvssString: string): number => {
  const res = calculateCvss(cvssString);

  return res.environmentalScore ?? res.temporalScore ?? res.baseScore;
};

/**
 * Calculate base score with impact and exploitability
 * @param cvssString - The CVSS vector string
 * @returns Score result with impact and exploitability
 */
export const calculateBaseResult = (cvssString: string): ScoreResult => {
  const res = calculateCvss(cvssString);

  return {
    score: res.baseScore,
    impact: res.baseImpact,
    exploitability: res.baseExploitability,
    metricsMap: res.metrics
  };
};

/**
 * Calculate temporal score with impact and exploitability
 * @param cvssString - The CVSS vector string
 * @returns Score result with impact and exploitability
 */
export const calculateTemporalResult = (cvssString: string): ScoreResult => {
  const res = calculateCvss(cvssString);

  return {
    score: res.temporalScore ?? res.baseScore,
    impact: res.baseImpact,
    exploitability: res.baseExploitability,
    metricsMap: res.metrics
  };
};

/**
 * Calculate environmental score with impact and exploitability
 * @param cvssString - The CVSS vector string
 * @returns Score result with impact and exploitability
 */
export const calculateEnvironmentalResult = (
  cvssString: string
): ScoreResult => {
  const res = calculateCvss(cvssString);

  return {
    score: res.environmentalScore ?? res.temporalScore ?? res.baseScore,
    impact:
      res.version === '2.0'
        ? res.baseImpact
        : res.modifiedImpact ?? res.baseImpact,
    exploitability:
      res.version === '2.0'
        ? res.baseExploitability
        : res.modifiedExploitability ?? res.baseExploitability,
    metricsMap: res.metrics
  };
};

export const parseMetricsAsMap = (cvssStr: string): Map<Metric, MetricValue> =>
  parseMetricsAsMapString(cvssStr) as Map<Metric, MetricValue>;

export const validateVersion = (versionStr: string | null): void => {
  if (!versionStr) {
    throw new Error(
      'Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L'
    );
  }

  if (versionStr !== '2.0' && versionStr !== '3.0' && versionStr !== '3.1') {
    throw new Error(
      `Unsupported CVSS version: ${versionStr}. Only 2.0, 3.0 and 3.1 are supported.`
    );
  }
};

// ============================================================================
// Re-exports for backward compatibility
// ============================================================================

export {
  calculateIss,
  calculateMiss,
  calculateExploitability,
  calculateModifiedExploitability,
  calculateImpact,
  calculateModifiedImpact,
  modifiedMetricsMap,
  populateTemporalMetricDefaults,
  populateEnvironmentalMetricDefaults,
  roundUp
} from './versions/v3/calculator';
export {
  humanizeBaseMetric,
  humanizeBaseMetricValue,
  humanizeScore
} from './versions/v3/humanizer';
export {
  BaseMetric,
  TemporalMetric,
  EnvironmentalMetric,
  type Metric,
  type Metrics,
  type BaseMetricValue,
  type TemporalMetricValue,
  type EnvironmentalMetricValue,
  type MetricValue,
  type MetricValues,
  baseMetrics,
  temporalMetrics,
  environmentalMetrics,
  baseMetricValues,
  temporalMetricValues,
  environmentalMetricValues
} from './versions/v3/models';
export {
  type KeyValue,
  parseVector,
  parseVersion,
  parseMetrics
} from './parser';
