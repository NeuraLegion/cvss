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
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:TF/RC:UR/CDP:L/TD:M/CR:M/IR:ND/AR:M':
    [7.5, 5.8, 4.7, 6.4, 10, 6.4, 10],
  'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:M/IR:M/AR:M/MAV:A/MAC:H/MPR:L/MUI:N/MS:X/MC:N/MI:H/MA:X':
    [5.1, 4.1, 5.2, 3.7, 0.9, 4.7, 1.3],
  'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N/E:U/RL:T/RC:C/CR:X/IR:L/AR:L/MAV:N/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L':
    [4.6, 4.1, 3.6, 2.5, 2.1, 2.5, 1.6]
};

describe('calculateBaseResult()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateBaseResult('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateBaseResult('CVSS:3.1/A:H')).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateBaseResult('CVSS:1.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
    ).to.throw();
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
});

describe('calculateTemporalResult()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateTemporalResult('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateTemporalResult('CVSS:3.1/A:H')).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateTemporalResult('CVSS:1.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
    ).to.throw();
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
    expect(() => calculateEnvironmentalResult('CVSS:3.1/A:H')).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateEnvironmentalResult(
        'CVSS:1.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N'
      )
    ).to.throw();
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

    it(`should calculate modified exploitability of ${modifiedImpact} for ${cvss}`, () => {
      expect(res.exploitability).to.equal(modifiedExploitability);
    });
  });
});

describe('calculateBaseScore()', () => {
  it('should throw an exception on empty value', () => {
    expect(() => calculateBaseScore('')).to.throw();
  });

  it('should throw an exception on missing mandatory metric', () => {
    expect(() => calculateBaseScore('CVSS:3.1/A:H')).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateBaseScore('CVSS:1.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
    ).to.throw();
  });

  Object.entries(cvssTests).map((entry) => {
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
    expect(() => calculateTemporalScore('CVSS:3.1/A:H')).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateTemporalScore('CVSS:1.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
    ).to.throw();
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
    expect(() => calculateEnvironmentalScore('CVSS:3.1/A:H')).to.throw();
  });

  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateEnvironmentalScore(
        'CVSS:1.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N'
      )
    ).to.throw();
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
