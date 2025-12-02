import { validate } from '../src/versions/v3/validator';
import { expect } from 'chai';

const cvss = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';

describe('validator v3', () => {
  it('should produce exception on string without version', () => {
    expect(() => validate(cvss.replace('CVSS:3.1', ''))).to.throw(
      'must start with'
    );
  });

  it('should not produce exception on valid 3.0 string', () => {
    expect(() => validate(cvss.replace('3.1', '3.0'))).not.to.throw();
  });

  it('should not produce exception on valid 3.1 string', () => {
    expect(() => validate(cvss)).to.not.throw();
  });

  it('should produce exception on unsupported 2.0 string', () => {
    expect(() => validate(`CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C`)).to.throw(
      /Unsupported.*2\.0/
    );
  });

  it('should produce exception on unsupported 1.0 string', () => {
    expect(() => validate(cvss.replace('3.1', '1.0'))).to.throw(
      /Unsupported.*1\.0/
    );
  });

  it('should produce exception on duplicated metric', () => {
    expect(() => validate(`${cvss}/AC:L`)).to.throw(/Duplicated.*AC:L/);
  });

  it('should produce exception on unknown metric', () => {
    expect(() => validate(`${cvss}/X:H`)).to.throw(/Unknown.*"X"/);
  });

  it('should produce exception on invalid metric value', () => {
    expect(() => validate(`${cvss}`.replace('PR:N', 'PR:X'))).to.throw(
      /Invalid.*PR.*X.*Allowed/
    );
  });

  it('should produce exception on missing mandatory metric', () => {
    expect(() => validate(`${cvss}`.replace('/C:H', ''))).to.throw(
      /Missing mandatory.*Confidentiality/
    );
  });

  it('should produce exception on double separator', () => {
    expect(() => validate(`${cvss}`.replace('N/S', 'N//S'))).to.throw(
      'Invalid'
    );
  });

  it('should not throw when validating extra scopes', () => {
    expect(() =>
      validate(
        `${cvss}/E:H/RL:U/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H`
      )
    ).not.to.throw();
  });
});
