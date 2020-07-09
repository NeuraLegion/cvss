import {
  BaseMetric,
  BaseMetricValue,
  humanizeBaseMetric,
  humanizeBaseMetricValue
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
});
