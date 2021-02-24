import {
  BaseMetric,
  BaseMetricValue,
  humanizeBaseMetric,
  humanizeBaseMetricValue,
  humanizeScore
} from '../src';
import { expect } from 'chai';

describe('humanizer', () => {
  it('should humanize base metric AV', () => {
    const result = humanizeBaseMetric(BaseMetric.ATTACK_VECTOR);
    expect(result).to.equal('Attack Vector');
  });

  it('should produce "Unknown" for unknown metric', () => {
    const result = humanizeBaseMetric(('X' as unknown) as BaseMetric);
    expect(result).to.equal('Unknown');
  });

  it('should humanize base metric AV value L', () => {
    const result = humanizeBaseMetricValue('L', BaseMetric.ATTACK_VECTOR);
    expect(result).to.equal('Local');
  });

  it('should humanize base metric A value L', () => {
    const result = humanizeBaseMetricValue('L', BaseMetric.AVAILABILITY);
    expect(result).to.equal('Low');
  });

  it('should humanize base metric AV value N', () => {
    const result = humanizeBaseMetricValue('N', BaseMetric.ATTACK_VECTOR);
    expect(result).to.equal('Network');
  });

  it('should humanize base metric C value N', () => {
    const result = humanizeBaseMetricValue('N', BaseMetric.CONFIDENTIALITY);
    expect(result).to.equal('None');
  });

  it('should produce "Unknown" for unknown value of existing metric', () => {
    const result = humanizeBaseMetricValue(
      ('X' as unknown) as BaseMetricValue,
      BaseMetric.SCOPE
    );
    expect(result).to.equal('Unknown');
  });

  it('should produce "Unknown" for unknown value of unknown metric', () => {
    const result = humanizeBaseMetricValue(
      ('X' as unknown) as BaseMetricValue,
      ('X' as unknown) as BaseMetric
    );
    expect(result).to.equal('Unknown');
  });

  it('should humanize score as "None" for zero value', () => {
    expect(humanizeScore(0)).to.equal('None');
  });

  it('should humanize score as "Low" for values from interval [0.1, 3.9]', () => {
    expect(humanizeScore(0.1)).to.equal('Low');
    expect(humanizeScore(1.2)).to.equal('Low');
    expect(humanizeScore(3.9)).to.equal('Low');
  });

  it('should humanize score as "Medium" for values from interval [4.0, 6.9]', () => {
    expect(humanizeScore(4.0)).to.equal('Medium');
    expect(humanizeScore(4.2)).to.equal('Medium');
    expect(humanizeScore(6.9)).to.equal('Medium');
  });

  it('should humanize score as "High" for values from interval [7.0, 8.9]', () => {
    expect(humanizeScore(7.0)).to.equal('High');
    expect(humanizeScore(7.5)).to.equal('High');
    expect(humanizeScore(8.9)).to.equal('High');
  });

  it('should humanize score as "Critical" for values from interval [9.0, 10.0]', () => {
    expect(humanizeScore(9.0)).to.equal('Critical');
    expect(humanizeScore(9.5)).to.equal('Critical');
    expect(humanizeScore(10.0)).to.equal('Critical');
  });
});
