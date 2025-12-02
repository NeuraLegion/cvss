import {
  calculateBaseResult,
  calculateBaseScore,
  calculateEnvironmentalResult,
  calculateEnvironmentalScore,
  calculateTemporalScore
} from '../src';
import { expect } from 'chai';

/* eslint-disable @typescript-eslint/naming-convention */

// CVSS => base, temporal, environmental, baseImpact, baseExploitability, modifiedImpact, modifiedExploitability
const cvssTests = {
  'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N': [
    8.6, 8.6, 8.6, 4, 3.9, 4, 3.9
  ],
  'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': [10, 10, 10, 6, 3.9, 6, 3.9],
  'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N': [0, 0, 0, 0, 2.5, 0, 2.5],
  'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H': [
    7.8, 7.8, 7.8, 5.9, 1.8, 5.9, 1.8
  ],
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N': [
    7.5, 7.5, 7.5, 3.6, 3.9, 3.6, 3.9
  ],
  'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N': [
    6.4, 6.4, 6.4, 2.7, 3.1, 2.7, 3.1
  ],
  'CVSS:3.1/S:C/C:L/I:L/A:N/AV:N/AC:L/PR:L/UI:N': [
    6.4, 6.4, 6.4, 2.7, 3.1, 2.7, 3.1
  ],
  'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N': [
    6.4, 6.4, 6.4, 2.7, 3.1, 2.7, 3.1
  ],
  'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N': [
    6.1, 6.1, 6.1, 2.7, 2.8, 2.7, 2.8
  ],
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N': [
    6.1, 6.1, 6.1, 2.7, 2.8, 2.7, 2.8
  ],
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N': [
    8.6, 8.6, 8.6, 4, 3.9, 4, 3.9
  ],
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': [
    10, 10, 10, 6, 3.9, 6.1, 3.9
  ],
  'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N': [0, 0, 0, 0, 2.5, 0, 2.5],
  'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H': [
    7.8, 7.8, 7.8, 5.9, 1.8, 5.9, 1.8
  ],
  'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:A/MAC:H/MPR:L/MUI:N/MS:X/MC:N/MI:H/MA:X':
    [5.1, 4.1, 5.2, 3.7, 0.9, 4.7, 1.3],
  'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N/E:U/RL:T/RC:C/CR:X/IR:L/AR:L/MAV:N/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L':
    [4.6, 4.1, 3.6, 2.5, 2.1, 2.5, 1.6],
  'CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N/E:P/RL:W/RC:C/IR:L/AR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:C/MI:L/MA:L':
    [3, 2.8, 4, 1.4, 1.3, 2.7, 1.3],
  'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:H/IR:H/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N':
    [5.1, 4.1, 0, 3.7, 0.9, 0, 0.2],
  'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:H/RL:U/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H':
    [5.1, 5.1, 10, 3.7, 0.9, 6.1, 3.9],
  'CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:M/IR:M/AR:L/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:N/MA:L':
    [3.8, 3.8, 2.4, 3.4, 0.4, 0.7, 1.6],
  'CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:N/MUI:R/MC:N/MI:H/MA:N':
    [3.8, 3.8, 4.8, 3.4, 0.4, 3.6, 1.2],
  'CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:N':
    [3.8, 3.8, 5.6, 3.4, 0.4, 4, 1.2],
  'CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/E:H/RL:U/RC:C/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:L':
    [6.2, 6.2, 6.1, 5.3, 0.4, 5.3, 0.4],
  'CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/E:H/RL:U/RC:C/MAV:P/MAC:H/MPR:N/MUI:R/MS:C/MC:L':
    [6.2, 6.2, 6.2, 5.3, 0.4, 5.3, 0.4],
  'CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L': [
    6.2, 6.2, 6.2, 5.3, 0.4, 5.3, 0.4
  ],
  'CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/CR:H': [
    6.2, 6.2, 6.4, 5.3, 0.4, 5.5, 0.4
  ],
  'CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/CR:H/IR:H/MAV:L/MUI:R/MS:U/MC:L':
    [6.2, 6.2, 7, 5.3, 0.4, 5.9, 1],
  'CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L': [
    6.2, 6.2, 6.1, 5.3, 0.4, 5.3, 0.4
  ],
  'CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L/MUI:R/MS:U/MC:L': [
    6.2, 6.2, 5.1, 5.3, 0.4, 4.7, 0.4
  ],
  'CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:A/MAC:L/MPR:L/MUI:N/MC:N/MI:H':
    [4.4, 3.5, 6.1, 3.7, 0.3, 4.7, 2.3],
  'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/RL:O/CR:L': [
    8.6, 8.2, 6, 4, 3.9, 1.9, 3.9
  ],
  'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N/E:P/RL:W/RC:R/CR:H/IR:M/AR:M/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:H/MA:L':
    [7.7, 6.8, 6.5, 4, 3.1, 5.5, 1.3],
  'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N/E:P/RL:W/RC:R/CR:H/IR:M/AR:M/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:H/MA:L':
    [7.7, 6.8, 6.5, 4, 3.1, 5.5, 1.3],
  'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': [
    9.6, 9.6, 9.6, 6, 2.8, 6, 2.8
  ],
  'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/MAV:A/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H':
    [9.6, 9.6, 9.6, 6, 2.8, 6, 2.8],
  'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': [
    9.6, 9.6, 9.7, 6, 2.8, 6.1, 2.8
  ],
  'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/MAV:A/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H':
    [9.6, 9.6, 9.7, 6, 2.8, 6.1, 2.8]
};

/* eslint-enable @typescript-eslint/naming-convention */

describe('Calculator', () => {
  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on empty value', () => {
    expect(() => calculateBaseScore('')).to.throw();
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on missing metric', () => {
    expect(() => calculateBaseScore('CVSS:3.1/A:H')).to.throw();
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateBaseScore('CVSS:2.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
    ).to.throw();
  });
});

describe('Calculate correctly base scores', () => {
  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const baseScore = entry[1][0];
    it(`should calculate a score of ${baseScore} for ${cvss}`, () => {
      const score = calculateBaseScore(cvss);
      expect(score).to.equal(baseScore);
    });
  });
});

describe('Calculate correctly base impact', () => {
  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const impact = entry[1][3];
    it(`should calculate impact of ${impact} for ${cvss}`, () => {
      const res = calculateBaseResult(cvss);
      expect(res.impact).to.equal(impact);
    });
  });
});

describe('Calculate correctly base exploitability', () => {
  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const exploitability = entry[1][4];
    it(`should calculate exploitability of ${exploitability} for ${cvss}`, () => {
      const res = calculateBaseResult(cvss);
      expect(res.exploitability).to.equal(exploitability);
    });
  });
});

describe('Calculate correctly temporal scores', () => {
  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const temporalScore = entry[1][1];
    it(`should calculate a score of ${temporalScore} for ${cvss}`, () => {
      const score = calculateTemporalScore(cvss);
      expect(score).to.equal(temporalScore);
    });
  });
});

describe('Calculate correctly environmental scores', () => {
  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const environmentalScore = entry[1][2];
    it(`should calculate a score of ${environmentalScore} for ${cvss}`, () => {
      const score = calculateEnvironmentalScore(cvss);
      expect(score).to.equal(environmentalScore);
    });
  });
});

describe('Calculate correctly modified impact', () => {
  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const impact = entry[1][5];
    it(`should calculate impact of ${impact} for ${cvss}`, () => {
      const res = calculateEnvironmentalResult(cvss);
      expect(res.impact).to.equal(impact);
    });
  });
});

describe('Calculate correctly modified exploitability', () => {
  Object.entries(cvssTests).map((entry) => {
    const cvss = entry[0];
    const exploitability = entry[1][6];
    it(`should calculate exploitability of ${exploitability} for ${cvss}`, () => {
      const res = calculateEnvironmentalResult(cvss);
      expect(res.exploitability).to.equal(exploitability);
    });
  });
});
