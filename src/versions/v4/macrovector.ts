import {
  BaseMetric,
  EnvironmentalMetric,
  Metric,
  MetricValue,
  ThreatMetric
} from './models';

export interface MacroVectorCode {
  eq1: number;
  eq2: number;
  eq3: number;
  eq4: number;
  eq5: number;
  eq6: number;
}

// A MacroVector is a cluster of CVSS v4 vectors with comparable qualitative severity,
// defined in equivalence-group space.
// There are six equivalence groups (EQ1–EQ6) used as dimensions.
export class MacroVector {
  public readonly coords: number[];

  constructor(metrics: Map<Metric, MetricValue>) {
    this.coords = [
      this.computeEq1(metrics),
      this.computeEq2(metrics),
      this.computeEq3(metrics),
      this.computeEq4(metrics),
      this.computeEq5(metrics),
      this.computeEq6(metrics)
    ];
  }

  public toString(): string {
    return this.coords.join('');
  }

  // eslint-disable-next-line complexity
  private computeEq1(metrics: Map<Metric, MetricValue>): number {
    const av = metrics.get(BaseMetric.ATTACK_VECTOR);
    const pr = metrics.get(BaseMetric.PRIVILEGES_REQUIRED);
    const ui = metrics.get(BaseMetric.USER_INTERACTION);

    if (av === 'N' && pr === 'N' && ui === 'N') {
      return 0;
    }

    if (
      (av === 'N' || pr === 'N' || ui === 'N') &&
      !(av === 'N' && pr === 'N' && ui === 'N') &&
      !(av === 'P')
    ) {
      return 1;
    }

    return 2;
  }

  private computeEq2(metrics: Map<Metric, MetricValue>): number {
    const ac = metrics.get(BaseMetric.ATTACK_COMPLEXITY);
    const at = metrics.get(BaseMetric.ATTACK_REQUIREMENTS);

    return ac === 'L' && at === 'N' ? 0 : 1;
  }

  private computeEq3(metrics: Map<Metric, MetricValue>): number {
    const vc = metrics.get(BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY);
    const vi = metrics.get(BaseMetric.VULNERABLE_SYSTEM_INTEGRITY);
    if (vc === 'H' && vi === 'H') {
      return 0;
    }

    const va = metrics.get(BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY);
    if (
      !(vc === 'H' && vi === 'H') &&
      (vc === 'H' || vi === 'H' || va === 'H')
    ) {
      return 1;
    }

    return 2;
  }

  private computeEq4(metrics: Map<Metric, MetricValue>): number {
    const si = metrics.get(BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY);
    const sa = metrics.get(BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY);
    if (si === 'S' || sa === 'S') {
      return 0;
    }

    const sc = metrics.get(BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY);
    if (sc === 'H' || si === 'H' || sa === 'H') {
      return 1;
    }

    return 2;
  }

  private computeEq5(metrics: Map<Metric, MetricValue>): number {
    const e = metrics.get(ThreatMetric.EXPLOIT_MATURITY);
    if (e === 'A') {
      return 0;
    }

    if (e === 'P') {
      return 1;
    }

    return 2;
  }

  private computeEq6(metrics: Map<Metric, MetricValue>): number {
    const cr = metrics.get(EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT);
    const vc = metrics.get(BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY);
    const ir = metrics.get(EnvironmentalMetric.INTEGRITY_REQUIREMENT);
    const vi = metrics.get(BaseMetric.VULNERABLE_SYSTEM_INTEGRITY);
    const ar = metrics.get(EnvironmentalMetric.AVAILABILITY_REQUIREMENT);
    const va = metrics.get(BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY);

    if (
      (cr === 'H' && vc === 'H') ||
      (ir === 'H' && vi === 'H') ||
      (ar === 'H' && va === 'H')
    ) {
      return 0;
    }

    return 1;
  }
}

export function getNeighborMacros(macro: MacroVector): string[][] {
  const [eq1, eq2, eq3, eq4, eq5, eq6] = macro.coords;

  const eq1Key = `${eq1 + 1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const eq2Key = `${eq1}${eq2 + 1}${eq3}${eq4}${eq5}${eq6}`;

  const eq3eq6: string[] = [];
  if ((eq3 === 1 && eq6 === 1) || (eq3 === 0 && eq6 === 1)) {
    eq3eq6.push(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`);
  } else if (eq3 === 1 && eq6 === 0) {
    eq3eq6.push(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`);
  } else if (eq3 === 0 && eq6 === 0) {
    eq3eq6.push(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`);
    eq3eq6.push(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`);
  }

  const eq4Key = `${eq1}${eq2}${eq3}${eq4 + 1}${eq5}${eq6}`;
  const eq5Key = `${eq1}${eq2}${eq3}${eq4}${eq5 + 1}${eq6}`;

  return [[eq1Key], [eq2Key], eq3eq6, [eq4Key], [eq5Key]];
}

// Canonical "maximum composed state" vectors from the CVSS v4.0 specification.
// EQ1–EQ5 (with EQ3/EQ6 sharing the nested eq3 entry) list the metric settings
// that produce the highest severity for each macro state; `getMaxVectorsForMacro`
// walks this table to expand a macro code into the spec-defined representative vectors.
/* eslint-disable @typescript-eslint/naming-convention */
const maxComposed: Record<string, any> = {
  eq1: {
    0: ['AV:N/PR:N/UI:N/'],
    1: ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
    2: ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/']
  },
  eq2: {
    0: ['AC:L/AT:N/'],
    1: ['AC:H/AT:N/', 'AC:L/AT:P/']
  },
  eq3eq6: {
    0: {
      0: ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
      1: ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/']
    },
    1: {
      0: ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
      1: [
        'VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/',
        'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
        'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/',
        'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
        'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/'
      ]
    },
    2: { 1: ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/'] }
  },
  eq4: {
    0: ['SC:H/SI:S/SA:S/'],
    1: ['SC:H/SI:H/SA:H/'],
    2: ['SC:L/SI:L/SA:L/']
  },
  eq5: {
    0: ['E:A/'],
    1: ['E:P/'],
    2: ['E:U/']
  }
};
/* eslint-enable @typescript-eslint/naming-convention */

export function getMaxMacroDistances({ coords }: MacroVector): number[] {
  // The maximal severity for each equivalence group level:
  // values are used to calculate the severity distance for interpolation
  const maxEqSeverity = [
    [1, 4, 5], // eq1
    [1, 2], // eq2
    // eq3eq6
    [
      [7, 6],
      [8, 8],
      [0, 10]
    ],
    // eq4
    [6, 5, 4],
    // eq5
    [1, 1, 1]
  ];

  return maxEqSeverity
    .map((eqs, i) =>
      i === 2
        ? (eqs as number[][])[coords[i]][coords[5]]
        : (eqs as number[])[coords[i]]
    )
    .map((s) => (s || 0) * 0.1);
}

type SeverityMetric =
  | BaseMetric.ATTACK_VECTOR
  | BaseMetric.PRIVILEGES_REQUIRED
  | BaseMetric.USER_INTERACTION
  | BaseMetric.ATTACK_COMPLEXITY
  | BaseMetric.ATTACK_REQUIREMENTS
  | BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY
  | BaseMetric.VULNERABLE_SYSTEM_INTEGRITY
  | BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY
  | BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY
  | BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY
  | BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY
  | EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT
  | EnvironmentalMetric.INTEGRITY_REQUIREMENT
  | EnvironmentalMetric.AVAILABILITY_REQUIREMENT;

const severityMetricLevels: Record<SeverityMetric, Record<string, number>> = {
  [BaseMetric.ATTACK_VECTOR]: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 },
  [BaseMetric.PRIVILEGES_REQUIRED]: { N: 0.0, L: 0.1, H: 0.2 },
  [BaseMetric.USER_INTERACTION]: { N: 0.0, P: 0.1, A: 0.2 },
  [BaseMetric.ATTACK_COMPLEXITY]: { L: 0.0, H: 0.1 },
  [BaseMetric.ATTACK_REQUIREMENTS]: { N: 0.0, P: 0.1 },
  [BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY]: { H: 0.0, L: 0.1, N: 0.2 },
  [BaseMetric.VULNERABLE_SYSTEM_INTEGRITY]: { H: 0.0, L: 0.1, N: 0.2 },
  [BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY]: { H: 0.0, L: 0.1, N: 0.2 },
  [BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY]: { H: 0.1, L: 0.2, N: 0.3 },
  [BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY]: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  [BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY]: {
    S: 0.0,
    H: 0.1,
    L: 0.2,
    N: 0.3
  },
  [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: { H: 0.0, M: 0.1, L: 0.2 },
  [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: { H: 0.0, M: 0.1, L: 0.2 },
  [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: { H: 0.0, M: 0.1, L: 0.2 }
};

const computeSeverityDistances = (
  metrics: Map<Metric, MetricValue>,
  vector: string
): Record<SeverityMetric, number> => {
  const vectorMetrics = (vector.split('/') || []).reduce((acc, item) => {
    const [key, value] = (item || '').split(':');

    return { ...acc, [key]: value };
  }, {} as Record<string, string>);

  const getSeverityLevel = (metric: SeverityMetric, value: string): number =>
    severityMetricLevels[metric][value] ?? 0;

  const dist = (metric: SeverityMetric): number =>
    getSeverityLevel(metric, metrics.get(metric) ?? '') -
    getSeverityLevel(metric, vectorMetrics[metric]);

  return {
    AV: dist(BaseMetric.ATTACK_VECTOR),
    PR: dist(BaseMetric.PRIVILEGES_REQUIRED),
    UI: dist(BaseMetric.USER_INTERACTION),
    AC: dist(BaseMetric.ATTACK_COMPLEXITY),
    AT: dist(BaseMetric.ATTACK_REQUIREMENTS),
    VC: dist(BaseMetric.VULNERABLE_SYSTEM_CONFIDENTIALITY),
    VI: dist(BaseMetric.VULNERABLE_SYSTEM_INTEGRITY),
    VA: dist(BaseMetric.VULNERABLE_SYSTEM_AVAILABILITY),
    SC: dist(BaseMetric.SUBSEQUENT_SYSTEM_CONFIDENTIALITY),
    SI: dist(BaseMetric.SUBSEQUENT_SYSTEM_INTEGRITY),
    SA: dist(BaseMetric.SUBSEQUENT_SYSTEM_AVAILABILITY),
    CR: dist(EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT),
    IR: dist(EnvironmentalMetric.INTEGRITY_REQUIREMENT),
    AR: dist(EnvironmentalMetric.AVAILABILITY_REQUIREMENT)
  };
};

export function getMaxVectorsForMacro(macro: MacroVector): string[] {
  const [eq1, eq2, eq3, eq4, eq5, eq6] = macro.coords;

  const eq1Maxes = maxComposed.eq1[eq1];
  const eq2Maxes = maxComposed.eq2[eq2];
  const eq3eq6Maxes = maxComposed.eq3eq6[eq3][eq6];
  const eq4Maxes = maxComposed.eq4[eq4];
  const eq5Maxes = maxComposed.eq5[eq5];

  const res: string[] = [];
  /* eslint-disable max-depth */
  for (const m1 of eq1Maxes) {
    for (const m2 of eq2Maxes) {
      for (const m3 of eq3eq6Maxes) {
        for (const m4 of eq4Maxes) {
          for (const m5 of eq5Maxes) {
            res.push(`${m1}${m2}${m3}${m4}${m5}`);
          }
        }
      }
    }
  }
  /* eslint-enable max-depth */

  return res;
}

export function getDistancesToMaxVector(
  metrics: Map<Metric, MetricValue>,
  maxVectors: string[]
): Record<SeverityMetric, number> {
  for (const maxVector of maxVectors) {
    const distances = computeSeverityDistances(metrics, maxVector);
    if (Object.values(distances).every((d) => d >= 0)) {
      return distances;
    }
  }

  // No valid max vector found; using first as fallback
  return computeSeverityDistances(metrics, maxVectors[0]);
}
