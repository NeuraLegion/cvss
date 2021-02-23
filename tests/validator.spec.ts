import { validate } from '../src';
import { expect } from 'chai';

describe('parser', () => {
  it('should produce exception on string without version', () => {
    expect(() => validate('/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).to.throw(
      'must start with'
    );
  });

  it('should not produce exception on valid 3.0 string', () => {
    expect(() =>
      validate('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).not.to.throw();
  });

  it('should not produce exception on valid 3.1 string', () => {
    expect(() =>
      validate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.not.throw();
  });

  it('should produce exception on unsupported 2.0 string', () => {
    expect(() =>
      validate('CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.throw(/Unsupported.*2\.0/);
  });

  it('should produce exception on unsupported 1.0 string', () => {
    expect(() =>
      validate('CVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.throw(/Unsupported.*1\.0/);
  });

  it('should produce exception on duplicated metric', () => {
    expect(() =>
      validate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/AC:L')
    ).to.throw(/Duplicated.*AC:L/);
  });

  it('should produce exception on unknown metric', () => {
    expect(() =>
      validate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/X:H/A:H')
    ).to.throw(/Unknown.*"X"/);
  });

  it('should produce exception on invalid metric value', () => {
    expect(() =>
      validate('CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:C/C:H/I:H/A:H')
    ).to.throw(/Invalid.*PR.*X.*Allowed/);
  });

  it('should produce exception on missing mandatory metric', () => {
    expect(() => validate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/I:H/A:H')).to.throw(
      /Missing mandatory.*Confidentiality/
    );
  });

  it('should produce exception on double separator', () => {
    expect(() =>
      validate('CVSS:3.1/AV:N/AC:L//PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.throw('Invalid');
  });

  it('should produce exception on double separator', () => {
    expect(() =>
      validate('CVSS:3.1/AV:N/AC:L//PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.throw('Invalid');
  });

  it('should not throw when validating extra scopes', () => {
    expect(() =>
      validate(
        'CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:H/RL:U/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H'
      )
    ).not.to.throw();
  });
});
