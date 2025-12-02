import type { CvssVersion } from './CvssVersion';

interface BaseCvssResult {
  version: CvssVersion;
  baseScore: number;
  metrics: Map<string, string>;
}

export interface CvssResultV3 extends BaseCvssResult {
  version: '3.0' | '3.1';

  /** Subscores for the Base score */
  baseImpact: number;
  baseExploitability: number;

  /** Temporal score (if temporal metrics defined) */
  temporalScore?: number;

  /** Environmental score (if env metrics defined) – "final adjusted" in v3.x */
  environmentalScore?: number;

  /** Subscores after Environmental modifications (optional) */
  modifiedImpact?: number;
  modifiedExploitability?: number;
}

export interface CvssResultV2 extends BaseCvssResult {
  version: '2.0';

  /** Subscores for the Base score */
  baseImpact: number;
  baseExploitability: number;

  /** Temporal score (if temporal metrics defined) */
  temporalScore?: number;

  /** Environmental score (if env metrics defined) */
  environmentalScore?: number;
}

export type CvssResult = CvssResultV3 | CvssResultV2;
