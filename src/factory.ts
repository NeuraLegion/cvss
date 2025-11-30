import type { CvssCalculator } from './common/CvssCalculator';
import type { CvssVersion } from './common/CvssVersion';
import { CvssV3Calculator } from './versions/v3/calculator';

export const createCvssCalculator = (version: CvssVersion): CvssCalculator => {
  switch (version) {
    case '3.0':
    case '3.1':
      return new CvssV3Calculator();
    default:
      throw new Error(`Unsupported CVSS version: ${version}`);
  }
};
