import { parseVersion, parseMetricsAsMap, parseVector } from '../src';
import { expect } from 'chai';

describe('parser', () => {
  it('should parse version (2.0)', () => {
    expect(parseVersion('CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C')).to.equal('2.0');
  });

  it('should parse version (3.0)', () => {
    expect(
      parseVersion('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.equal('3.0');
  });

  it('should parse version (3.1)', () => {
    expect(
      parseVersion('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.equal('3.1');
  });

  it('should parse vector (2.0)', () => {
    expect(parseVector('CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C')).to.equal(
      'AV:N/AC:L/Au:N/C:N/I:N/A:C'
    );
  });

  it('should parse vector (3.1)', () => {
    expect(
      parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    ).to.equal('AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  });

  it('should parse metrics as map (2.0)', () => {
    expect(
      parseMetricsAsMap('CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C')
    ).to.deep.equal(
      new Map<string, string>([
        ['AV', 'N'],
        ['AC', 'L'],
        ['Au', 'N'],
        ['C', 'N'],
        ['I', 'N'],
        ['A', 'C']
      ])
    );
  });

  it('should parse metrics as map (3.1)', () => {
    expect(parseMetricsAsMap('CVSS:3.1/AV:N/AC:L')).to.deep.equal(
      new Map<string, string>([
        ['AV', 'N'],
        ['AC', 'L']
      ])
    );
  });

  it('should throw an exception on duplicated metric (2.0)', () => {
    expect(() =>
      parseMetricsAsMap('CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C/AV:N')
    ).to.throw();
  });

  it('should throw an exception on duplicated metric (3.1)', () => {
    expect(() =>
      parseMetricsAsMap('CVSS:3.1/AV:N/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
    ).to.throw();
  });
});
