import type { CvssResult } from './common/CvssResult';
import type { CvssVersion } from './common/CvssVersion';
import { createCvssCalculator } from './factory';
import { parseVersion } from './versions/v3/parser';

// ============================================================================
// Backward Compatible Public API
// ============================================================================

export interface ScoreResult {
  score: number;
  impact: number;
  exploitability: number;
  metricsMap: Map<string, string>;
}

function calculateCvss(cvssString: string): CvssResult {
  const version = parseVersion(cvssString);
  if (!version) {
    throw new Error('Invalid CVSS string: unable to detect version');
  }

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
    impact: res.environmentalImpact ?? res.baseImpact,
    exploitability: res.environmentalExploitability ?? res.baseExploitability,
    metricsMap: res.metrics
  };
};

// ============================================================================
// Re-exports for backward compatibility
// ============================================================================

export * from './versions/v3/humanizer';
export * from './versions/v3/models';
export {
  parseVector,
  parseVersion,
  parseMetrics,
  parseMetricsAsMap
} from './versions/v3/parser';
export { validate } from './versions/v3/validator';
