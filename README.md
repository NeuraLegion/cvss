# cvss

The Common Vulnerability Scoring System ([CVSS](https://www.first.org/cvss/)) [base](https://www.first.org/cvss/specification-document#Base-Metrics) [score](https://www.first.org/cvss/specification-document#1-2-Scoring) calculator and validator library written in [TypeScript](https://www.typescriptlang.org/).

## Basics 🧾

CVSS outputs numerical scores, indicating severity of vulnerability, based on some principal technical vulnerability characteristics.
Its outputs include numerical scores indicating the severity of a vulnerability relative to other vulnerabilities. [Link](https://www.first.org/cvss/v3.1/specification-document#Introduction)

The CVSS v3 vector string begins with the label `CVSS:` and numeric representation of the version.
After version string, it contains a set of `/`-separated CVSS metrics.
Each metric consists of name and value (both abbreviated) separated with ':'.

### Sample

Sample CVSS v3.1 vector string: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N`

Score is: [3.8](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N), severity: [Low](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N)

### Current library limitations 🚧

CVSS specification defines three metric groups: `Base`, `Temporal`, and `Environmental`, but only `Base` metrics are supported by given library for now.

Supported CVSS versions: [3.0](https://www.first.org/cvss/v3-0/) and [3.1](https://www.first.org/cvss/v3-1/)

## Install 🚀

`npm i --save @neuralegion/cvss`

## API

<details>
<summary>Score Calculator</summary>

`calculateBaseScore(cvssString): number`

Calculates [Base Score](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations),
which depends on sub-formulas for Impact Sub-Score (ISS), Impact, and Exploitability,

`calculateIss(metricsMap): number`

Calculates [Impact Sub-Score (ISS)](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations)

`calculateImpact(metricsMap, iss): number`

Calculates [Impact](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations)

`calculateExploitability(metricsMap): number`

Calculates [Exploitability](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations)

</details>

<details>
<summary>Validator</summary>

`validate(cvssString): void`

Throws an Error if given CVSS string is either invalid or unsupported.

Error contains verbose message with error details. Sample error messages:

- CVSS vector must start with "CVSS:"
- Invalid CVSS string. Example: CVSS:2.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L
- Unsupported CVSS version: 2.0. Only 3.0 and 3.1 are supported
- Duplicated metric: "AC:L"
- Missing mandatory CVSS base metric C (Confidentiality)
- Unknown CVSS metric "X". Allowed metrics: AV, AC, PR, UI, S, C, I, A
- Invalid value for CVSS metric PR (Privileges Required): Y. Allowed values: N (None), L (Low), H (High)
</details>

<details>
<summary>Humanizer</summary>

`humanizeBaseMetric(metric)`

Return un-abbreviated metric name: e.g. 'Confidentiality' for input 'C'

`humanizeBaseMetricValue(value, metric)`

Return un-abbreviated metric value: e.g. 'Network' for input ('AV', 'N')

</details>

## Usage

<details>
<summary>ECMAScript 2015, Typescript modules</summary>

```
import { calculateBaseScore } from '@neuralegion/cvss';

console.log('score: ', calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'));
```

</details>

<details>
<summary>NodeJS (CommonJS module)</summary>

```
const cvss = require('@neuralegion/cvss');

console.log(cvss.calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'));
```

</details>

<details>

<summary>NodeJS (experimental ESM support)</summary>

`usage.mjs` file:

```
import cvss from '@neuralegion/cvss';

console.log(cvss.calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'));
```

Running: `node --experimental-modules ./usage.mjs`

</details>

<details>
<summary>Browser (globals from umd bundle)</summary>

```
<script src="./node_modules/@neuralegion/cvss/dist/bundle.umd.js"></script>
<script>
  alert(`Score: ${cvss.calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N')}`);
</script>
```

</details>

<details>
<summary>Browser (ES modules)</summary>) 

```
<script type="module">
  import { calculateBaseScore } from './node_modules/@neuralegion/cvss/dist/bundle.es.js';
  alert(`Score: ${calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N')}`);
</script>
```

</details>

## Development 🛠

Issues and pull requests are highly welcome. 👍

Please, don't forget to lint (`npm run lint`) and test (`npm t`) the code.

## License

Copyright © 2020 [NeuraLegion](https://github.com/NeuraLegion).

This project is licensed under the MIT License - see the [LICENSE file](LICENSE) for details.
