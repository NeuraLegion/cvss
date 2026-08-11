import {
  calculateBaseResult,
  calculateTemporalResult,
  calculateEnvironmentalResult,
  calculateBaseScore,
  calculateTemporalScore,
  calculateEnvironmentalScore
} from '../src';
import { expect } from 'chai';

/* eslint-disable @typescript-eslint/naming-convention */

// CVSS => baseScore, temporalScore, environmentalScore, impact, exploitability, modifiedImpact, modifiedExploitability
const cvssTests: Record<string, number[]> = {
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:N/E:U/RL:W/RC:ND/CDP:N/TD:ND/CR:L/IR:M/AR:L':
    [6.4, 5.2, 4.6, 4.9, 10, 4.9, 10],
  'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N': [
    8.6, 8.6, 8.6, 4, 3.9, 4, 3.9
  ],
  'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:A/MAC:H/MPR:L/MUI:N/MS:X/MC:N/MI:H/MA:X':
    [5.1, 4.1, 5.2, 3.7, 0.9, 4.7, 1.3]
};

const cvssV4Sample =
  'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X';

const cvssTestsAll: Record<string, number[]> = {
  ...cvssTests,
  // CVSS v4 => baseScore
  [cvssV4Sample]: [2.3]
};

const cvssMissingMetric = 'CVSS:3.1/A:H';
const cvssUnsupportedVersion = 'CVSS:1.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N';

describe('calculateBaseResult()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateBaseResult('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateBaseResult(cvssMissingMetric)).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() => calculateBaseResult(cvssUnsupportedVersion)).to.throw();
  });

  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const baseScore = entry[1][0];
    const impact = entry[1][3];
    const exploitability = entry[1][4];

    const res = calculateBaseResult(cvss);

    it(`should calculate a score of ${baseScore} for ${cvss}`, () => {
      expect(res.score).to.equal(baseScore);
    });

    it(`should calculate impact of ${impact} for ${cvss}`, () => {
      expect(res.impact).to.equal(impact);
    });

    it(`should calculate exploitability of ${exploitability} for ${cvss}`, () => {
      expect(res.exploitability).to.equal(exploitability);
    });
  });

  Object.entries(cvssTestsAll).map((entry) => {
    const cvss = entry[0];
    const baseScore = entry[1][0];

    const res = calculateBaseResult(cvss);

    it(`should calculate a base score of ${baseScore} for ${cvss}`, () => {
      expect(res.score).to.equal(baseScore);
    });
  });
});

describe('calculateTemporalResult()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateTemporalResult('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateTemporalResult(cvssMissingMetric)).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() => calculateTemporalResult(cvssUnsupportedVersion)).to.throw();
  });

  it('should throw an exception on CVSS v4', () => {
    expect(() => calculateTemporalResult(cvssV4Sample)).to.throw(
      'Only base score calculation is supported for CVSS v4.0'
    );
  });

  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const temporalScore = entry[1][1];

    const res = calculateTemporalResult(cvss);

    it(`should calculate a score of ${temporalScore} for ${cvss}`, () => {
      expect(res.score).to.equal(temporalScore);
    });
  });
});

describe('calculateEnvironmentalResult()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateEnvironmentalResult('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateEnvironmentalResult(cvssMissingMetric)).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateEnvironmentalResult(cvssUnsupportedVersion)
    ).to.throw();
  });

  it('should throw an exception on CVSS v4', () => {
    expect(() => calculateEnvironmentalResult(cvssV4Sample)).to.throw(
      'Only base score calculation is supported for CVSS v4.0'
    );
  });

  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const environmentalScore = entry[1][2];
    const modifiedImpact = entry[1][5];
    const modifiedExploitability = entry[1][6];

    const res = calculateEnvironmentalResult(cvss);

    it(`should calculate a score of ${environmentalScore} for ${cvss}`, () => {
      expect(res.score).to.equal(environmentalScore);
    });

    it(`should calculate modified impact of ${modifiedImpact} for ${cvss}`, () => {
      expect(res.impact).to.equal(modifiedImpact);
    });

    it(`should calculate modified exploitability of ${modifiedExploitability} for ${cvss}`, () => {
      expect(res.exploitability).to.equal(modifiedExploitability);
    });
  });
});

describe('calculateBaseScore()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateBaseScore('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateBaseScore(cvssMissingMetric)).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() => calculateBaseScore(cvssUnsupportedVersion)).to.throw();
  });

  Object.entries(cvssTestsAll).map((entry) => {
    const cvss = entry[0];
    const expectedScore = entry[1][0];
    const score = calculateBaseScore(cvss);

    it(`should calculate a base score of ${expectedScore} for ${cvss}`, () => {
      expect(score).to.equal(expectedScore);
    });
  });
});

describe('calculateTemporalScore()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateTemporalScore('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateTemporalScore(cvssMissingMetric)).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() => calculateTemporalScore(cvssUnsupportedVersion)).to.throw();
  });

  it('should throw an exception on CVSS v4', () => {
    expect(() => calculateTemporalScore(cvssV4Sample)).to.throw(
      'Only base score calculation is supported for CVSS v4.0'
    );
  });

  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const expectedScore = entry[1][1];
    const score = calculateTemporalScore(cvss);

    it(`should calculate a temporal score of ${expectedScore} for ${cvss}`, () => {
      expect(score).to.equal(expectedScore);
    });
  });
});

describe('calculateEnvironmentalScore()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateEnvironmentalScore('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateEnvironmentalScore(cvssMissingMetric)).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateEnvironmentalScore(cvssUnsupportedVersion)
    ).to.throw();
  });

  it('should throw an exception on CVSS v4', () => {
    expect(() => calculateEnvironmentalScore(cvssV4Sample)).to.throw(
      'Only base score calculation is supported for CVSS v4.0'
    );
  });

  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const expectedScore = entry[1][2];
    const score = calculateEnvironmentalScore(cvss);

    it(`should calculate an environmental score of ${expectedScore} for ${cvss}`, () => {
      expect(score).to.equal(expectedScore);
    });
  });
});
