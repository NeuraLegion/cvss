import type { CvssCalculator } from './common/CvssCalculator';
import type { CvssVersion } from './common/CvssVersion';
import { CvssV3Calculator } from './versions/v3/calculator';
import { CvssV2Calculator } from './versions/v2/calculator';
import { CvssV4Calculator } from './versions/v4/calculator';

export const createCvssCalculator = (version: CvssVersion): CvssCalculator => {
  switch (version) {
    case '2.0':
      return new CvssV2Calculator();
    case '3.0':
    case '3.1':
      return new CvssV3Calculator();
    case '4.0':
      return new CvssV4Calculator();
    default:
      throw new Error(`Unsupported CVSS version: ${version}`);
  }
};
