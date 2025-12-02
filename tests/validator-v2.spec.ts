import { validate } from '../src/versions/v2/validator';
import { expect } from 'chai';

const cvss = 'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C';

describe('validator v2', () => {
  it('should produce exception on string without version', () => {
    expect(() => validate(cvss.replace('CVSS:2.0', ''))).to.throw(
      'must start with'
    );
  });

  it('should not produce exception on valid 2.0 string', () => {
    expect(() => validate(cvss)).not.to.throw();
  });

  it('should produce exception on unsupported 3.0 string', () => {
    expect(() =>
      validate(`CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)
    ).to.throw(/Unsupported.*3\.0/);
  });

  it('should produce exception on unsupported 1.0 string', () => {
    expect(() => validate(cvss.replace('2.0', '1.0'))).to.throw(
      /Unsupported.*1\.0/
    );
  });

  it('should produce exception on duplicated metric', () => {
    expect(() => validate(`${cvss}/AC:L`)).to.throw(/Duplicated.*AC:L/);
  });

  it('should produce exception on unknown metric', () => {
    expect(() => validate(`${cvss}/X:L`)).to.throw(/Unknown.*"X"/);
  });

  it('should produce exception on invalid metric value', () => {
    expect(() => validate(cvss.replace('Au:N', 'Au:X'))).to.throw(
      /Invalid.*Au.*X.*Allowed/
    );
  });

  it('should produce exception on missing mandatory metric', () => {
    expect(() => validate(cvss.replace('/C:N', ''))).to.throw(
      /Missing mandatory.*Confidentiality Impact/
    );
  });

  it('should produce exception on double separator', () => {
    expect(() => validate(cvss.replace('N/AC', 'N//AC'))).to.throw('Invalid');
  });

  it('should not throw when validating extra scopes', () => {
    expect(() =>
      validate(`${cvss}/E:U/RL:OF/RC:UC/CDP:N/TD:L/CR:H/IR:ND/AR:L`)
    ).not.to.throw();
  });
});
