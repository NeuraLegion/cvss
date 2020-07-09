import { calculateBaseScore } from '../src';
import { expect } from 'chai';

describe('calculator', () => {
  it('should calculate "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" score as 8.6', () => {
    const result = calculateBaseScore(
      'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'
    );
    expect(result).to.equal(8.6);
  });

  it('should calculate "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" score as 10.0', () => {
    const result = calculateBaseScore(
      'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
    );
    expect(result).to.equal(10);
  });

  it('should calculate "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N" score as 0.0', () => {
    const result = calculateBaseScore(
      'CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N'
    );
    expect(result).to.equal(0);
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should calculate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" score as 7.5', () => {
    const result = calculateBaseScore(
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
    );
    expect(result).to.equal(7.5);
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should calculate "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" score as 7.8', () => {
    const result = calculateBaseScore(
      'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
    );
    expect(result).to.equal(7.8);
  });

  // https://www.first.org/cvss/user-guide#3-6-Vulnerable-Components-Protected-by-a-Firewall
  it('should calculate "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N" score as 6.4', () => {
    const result = calculateBaseScore(
      'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N'
    );
    expect(result).to.equal(6.4);
  });

  it('should calculate "CVSS:3.1/S:C/C:L/I:L/A:N/AV:N/AC:L/PR:L/UI:N" (non-normalized order) score as 6.4', () => {
    const result = calculateBaseScore(
      'CVSS:3.1/S:C/C:L/I:L/A:N/AV:N/AC:L/PR:L/UI:N'
    );
    expect(result).to.equal(6.4);
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on empty value', () => {
    expect(() => calculateBaseScore('')).to.throw();
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on missing metric', () => {
    expect(() => calculateBaseScore('CVSS:3.0/A:H')).to.throw();
  });

  // https://www.first.org/cvss/user-guide#3-1-CVSS-Scoring-in-the-Exploit-Life-Cycle
  it('should throw an exception on unsupported version', () => {
    expect(() =>
      calculateBaseScore('CVSS:2.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
    ).to.throw();
  });
});
