import type { CvssResult } from './CvssResult';

export interface CvssCalculator {
  calculate(cvssString: string): CvssResult;
}
