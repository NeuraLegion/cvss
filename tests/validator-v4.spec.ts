import { validate } from '../src/versions/v4/validator';
import { expect } from 'chai';

const cvss = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N';

describe('validator v4', () => {
  it('should produce exception on string without version', () => {
    expect(() => validate(cvss.replace('CVSS:4.0', ''))).to.throw(
      'must start with'
    );
  });

  it('should not produce exception on valid 4.0 string', () => {
    expect(() => validate(cvss)).to.not.throw();
  });

  it('should produce exception on unsupported 1.0 string', () => {
    expect(() => validate(cvss.replace('4.0', '1.0'))).to.throw(
      /Unsupported.*1\.0/
    );
  });

  it('should produce exception on duplicated metric', () => {
    expect(() => validate(`${cvss}/AV:N`)).to.throw(/Duplicated.*AV:N/);
  });

  it('should produce exception on unknown metric', () => {
    expect(() => validate(`${cvss}/X:H`)).to.throw(/Unknown.*"X"/);
  });

  it('should produce exception on invalid metric value', () => {
    expect(() => validate(`${cvss}`.replace('AT:N', 'AT:X'))).to.throw(
      /Invalid.*AT.*X.*Allowed/
    );
  });

  it('should produce exception on missing mandatory metric', () => {
    expect(() => validate(`${cvss}`.replace('/AV:N', ''))).to.throw(
      /Missing mandatory.*AV/
    );
  });

  it('should produce exception on double separator', () => {
    expect(() => validate(`${cvss}`.replace('N/AC', 'N//AC'))).to.throw(
      'Invalid'
    );
  });

  it('should not throw when validating extra scopes', () => {
    expect(() =>
      validate(
        `${cvss}/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:P/MPR:L/MUI:P/MVC:L/MVI:L/MVA:L/MSC:N/MSI:N/MSA:N/S:N/AU:Y/R:A/V:D/RE:L/U:Green`
      )
    ).not.to.throw();
  });
});
