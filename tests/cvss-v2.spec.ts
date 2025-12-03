import { CvssV2Calculator } from '../src/versions/v2/calculator';
import { expect } from 'chai';

/* eslint-disable @typescript-eslint/naming-convention */

// Base metrics collected from https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2020.json.gz
// CVSS => baseScore, impact, exploitability, temporalScore (optional), environmentalScore (optional)
const cvssTests: Record<string, number[]> = {
  'CVSS:2.0/AV:N/AC:L/Au:S/C:C/I:C/A:C': [9, 10, 8],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:P': [6.8, 6.4, 8.6],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P': [7.5, 6.4, 10],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:N/A:P': [5.8, 4.9, 8.6],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:N/A:C': [7.1, 6.9, 8.6],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:N': [6.4, 4.9, 10],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:P/A:N': [4.3, 2.9, 8.6],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:N/I:P/A:N': [3.5, 2.9, 6.8],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:P/I:P/A:P': [6.5, 6.4, 8],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N': [5, 2.9, 10],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:C/I:N/A:N': [6.8, 6.9, 8],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:P/A:N': [4, 2.9, 8],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:N/I:P/A:N': [2.1, 2.9, 3.9],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P': [5, 2.9, 10],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C': [10, 10, 10],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:C': [7.2, 10, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:C/A:C': [9.3, 10, 8.6],
  'CVSS:2.0/AV:L/AC:H/Au:N/C:P/I:P/A:P': [3.7, 6.4, 1.9],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:N/I:N/A:C': [4.9, 6.9, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:N/A:N': [4.3, 2.9, 8.6],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:N/A:N': [2.1, 2.9, 3.9],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:P/I:N/A:N': [1.9, 2.9, 3.4],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:N/A:P': [4.3, 2.9, 8.6],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:P/I:P/A:N': [5.5, 4.9, 8],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:P/A:N': [5, 2.9, 10],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:P/I:N/A:N': [3.5, 2.9, 6.8],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:P/I:N/A:N': [4, 2.9, 8],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:P': [6.4, 4.9, 10],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:P/A:P': [4.6, 6.4, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:N': [5.8, 4.9, 8.6],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:P/I:P/A:P': [5.1, 6.4, 4.9],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:C/I:C/A:C': [7.6, 10, 4.9],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:N/A:C': [6.8, 6.9, 8],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:C/I:C/A:C': [8.3, 10, 6.5],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C': [7.8, 6.9, 10],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:N/A:P': [4, 2.9, 8],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:P/I:P/A:P': [6, 6.4, 6.8],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:N/I:P/A:P': [4.9, 4.9, 6.8],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:P/I:N/A:N': [2.6, 2.9, 4.9],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:P/A:P': [6.4, 4.9, 10],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:P/I:P/A:N': [4.9, 4.9, 6.8],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:P/A:N': [3.6, 4.9, 3.9],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:P/I:P/A:P': [4.4, 6.4, 3.4],
  'CVSS:2.0/AV:N/AC:H/Au:S/C:N/I:P/A:N': [2.1, 2.9, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:P/A:P': [5.8, 4.9, 8.6],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:N/I:P/A:P': [3.3, 4.9, 3.4],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:N/I:P/A:N': [1.9, 2.9, 3.4],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:N/I:N/A:P': [2.1, 2.9, 3.9],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:N/I:P/A:P': [3.6, 4.9, 3.9],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:N/I:N/A:P': [1.9, 2.9, 3.4],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:P/I:P/A:N': [3.3, 4.9, 3.4],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:N/I:N/A:P': [3.3, 2.9, 6.5],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:N/I:P/A:N': [2.6, 2.9, 4.9],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:N/A:P': [3.6, 4.9, 3.9],
  'CVSS:2.0/AV:A/AC:H/Au:N/C:P/I:P/A:P': [4.3, 6.4, 3.2],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:N/A:N': [7.8, 6.9, 10],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:C/A:P': [8.5, 7.8, 10],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:N/I:N/A:C': [6.1, 6.9, 6.5],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:P/I:N/A:P': [5.5, 4.9, 8],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:C/I:C/A:C': [8.5, 10, 6.8],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:N/I:N/A:C': [5.5, 6.9, 5.1],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:P/I:P/A:N': [4, 4.9, 4.9],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:N/A:N': [4.9, 6.9, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:N/I:N/A:C': [6.3, 6.9, 6.8],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:C/I:N/A:N': [4.7, 6.9, 3.4],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:N/A:N': [7.1, 6.9, 8.6],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:C/I:C/A:C': [6.9, 10, 3.4],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:P/I:P/A:P': [5.8, 6.4, 6.5],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:N/I:N/A:P': [3.5, 2.9, 6.8],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:N/I:C/A:N': [4.9, 6.9, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:C/A:N': [8.8, 9.2, 8.6],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:C/I:C/A:C': [7.7, 10, 5.1],
  'CVSS:2.0/AV:L/AC:H/Au:N/C:N/I:P/A:P': [2.6, 4.9, 1.9],
  'CVSS:2.0/AV:A/AC:M/Au:N/C:P/I:P/A:P': [5.4, 6.4, 5.5],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:N/I:P/A:N': [3.3, 2.9, 6.5],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:P/I:N/A:N': [3.3, 2.9, 6.5],
  'CVSS:2.0/AV:A/AC:M/Au:N/C:P/I:P/A:N': [4.3, 4.9, 5.5],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:C/A:C': [8.5, 9.2, 8],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:P/A:P': [5.5, 4.9, 8],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:N/I:P/A:C': [5.6, 7.8, 3.9],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:N/I:C/A:C': [6.6, 9.2, 3.9],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:C/A:C': [9.4, 9.2, 10],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:N': [6.6, 9.2, 3.9],
  'CVSS:2.0/AV:A/AC:M/Au:S/C:P/I:P/A:P': [4.9, 6.4, 4.4],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:N/I:P/A:C': [5.4, 7.8, 3.4],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:N/A:C': [6.6, 9.2, 3.9],
  'CVSS:2.0/AV:A/AC:M/Au:N/C:P/I:N/A:N': [2.9, 2.9, 5.5],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:P/I:P/A:P': [5.2, 6.4, 5.1],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:C': [9, 8.5, 10],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:P/I:P/A:C': [8, 8.5, 8],
  'CVSS:2.0/AV:A/AC:M/Au:S/C:P/I:N/A:N': [2.3, 2.9, 4.4],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:P/A:C': [8.5, 7.8, 10],
  'CVSS:2.0/AV:N/AC:H/Au:S/C:P/I:P/A:P': [4.6, 6.4, 3.9],
  'CVSS:2.0/AV:L/AC:H/Au:N/C:P/I:N/A:N': [1.2, 2.9, 1.9],
  'CVSS:2.0/AV:N/AC:H/Au:S/C:P/I:P/A:N': [3.6, 4.9, 3.9],
  'CVSS:2.0/AV:A/AC:M/Au:S/C:C/I:C/A:C': [7.4, 10, 4.4],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:N/A:C': [9.4, 9.2, 10],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:P/I:P/A:C': [5.9, 8.5, 3.4],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:P/I:P/A:N': [4.8, 4.9, 6.5],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:N/I:N/A:C': [5.4, 6.9, 4.9],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:C/A:C': [6.8, 9.5, 3.9],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:N/I:N/A:P': [2.6, 2.9, 4.9],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:N/I:N/A:C': [4.7, 6.9, 3.4],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:P/I:N/A:P': [4.9, 4.9, 6.8],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:P/I:P/A:C': [6.7, 8.5, 5.1],
  'CVSS:2.0/AV:L/AC:L/Au:S/C:P/I:N/A:N': [1.7, 2.9, 3.1],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:N/I:P/A:P': [4.8, 4.9, 6.5],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:N/I:C/A:C': [6.3, 9.2, 3.4],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:N/I:P/A:C': [6.8, 7.8, 6.5],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:P/A:C': [6.1, 8.5, 3.9],
  'CVSS:2.0/AV:L/AC:H/Au:N/C:C/I:C/A:C': [6.2, 10, 1.9],
  'CVSS:2.0/AV:N/AC:H/Au:S/C:P/I:N/A:N': [2.1, 2.9, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:N/A:C': [7.8, 7.8, 8.6],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:C/I:N/A:N': [5.4, 6.9, 4.9],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:P/I:N/A:N': [2.7, 2.9, 5.1],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:P/I:N/A:P': [4.8, 4.9, 6.5],
  'CVSS:2.0/AV:A/AC:M/Au:N/C:C/I:C/A:C': [7.9, 10, 5.5],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:N/I:N/A:P': [2.7, 2.9, 5.1],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:P/I:N/A:P': [3.3, 4.9, 3.4],
  'CVSS:2.0/AV:A/AC:M/Au:N/C:N/I:N/A:P': [2.9, 2.9, 5.5],
  'CVSS:2.0/AV:L/AC:M/Au:S/C:P/I:P/A:N': [3, 4.9, 2.7],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:P/I:P/A:C': [7.5, 8.5, 6.8],
  'CVSS:2.0/AV:L/AC:H/Au:N/C:N/I:P/A:N': [1.2, 2.9, 1.9],
  'CVSS:2.0/AV:N/AC:H/Au:S/C:N/I:N/A:P': [2.1, 2.9, 3.9],
  'CVSS:2.0/AV:N/AC:H/Au:N/C:N/I:P/A:P': [4, 4.9, 4.9],
  'CVSS:2.0/AV:N/AC:H/Au:S/C:C/I:C/A:C': [7.1, 10, 3.9],
  'CVSS:2.0/AV:A/AC:M/Au:S/C:N/I:P/A:N': [2.3, 2.9, 4.4],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:C/A:N': [7.1, 6.9, 8.6],
  'CVSS:2.0/AV:L/AC:H/Au:N/C:C/I:C/A:P': [5.9, 9.5, 1.9],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:P/I:P/A:N': [4.1, 4.9, 5.1],
  'CVSS:2.0/AV:L/AC:L/Au:S/C:N/I:N/A:C': [4.6, 6.9, 3.1],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:C/I:C/A:P': [7.4, 9.5, 5.1],
  'CVSS:2.0/AV:A/AC:M/Au:N/C:N/I:N/A:C': [5.7, 6.9, 5.5],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:P/A:C': [7.8, 7.8, 8.6],
  'CVSS:2.0/AV:A/AC:L/Au:N/C:N/I:C/A:C': [7.8, 9.2, 6.5],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:P/A:C': [7.5, 7.8, 8],
  'CVSS:2.0/AV:A/AC:H/Au:S/C:P/I:P/A:P': [4, 6.4, 2.5],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:P/A:N': [7.8, 7.8, 8.6],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:C/I:C/A:N': [7.9, 9.2, 6.8],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:C/I:C/A:N': [8.5, 9.2, 8],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:N': [9.4, 9.2, 10],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:P/A:N': [8.5, 7.8, 10],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:C/I:P/A:N': [7.5, 7.8, 8],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:N/A:C': [5.6, 7.8, 3.9],
  'CVSS:2.0/AV:A/AC:M/Au:N/C:N/I:P/A:N': [2.9, 2.9, 5.5],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:N/I:P/A:N': [2.7, 2.9, 5.1],
  'CVSS:2.0/AV:N/AC:H/Au:S/C:P/I:N/A:P': [3.6, 4.9, 3.9],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:C/I:N/A:N': [6.3, 6.9, 6.8],
  'CVSS:2.0/AV:L/AC:M/Au:N/C:P/I:N/A:C': [5.4, 7.8, 3.4],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:C': [8.3, 8.5, 8.6],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:P/I:N/A:C': [7.5, 7.8, 8],
  'CVSS:2.0/AV:L/AC:L/Au:S/C:P/I:P/A:P': [4.3, 6.4, 3.1],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:C': [8.5, 7.8, 10],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:P': [9.7, 9.5, 10],
  'CVSS:2.0/AV:A/AC:M/Au:S/C:P/I:P/A:N': [3.8, 4.9, 4.4],
  'CVSS:2.0/AV:A/AC:H/Au:N/C:P/I:N/A:N': [1.8, 2.9, 3.2],
  'CVSS:2.0/AV:A/AC:M/Au:S/C:N/I:N/A:P': [2.3, 2.9, 4.4],
  'CVSS:2.0/AV:A/AC:L/Au:S/C:P/I:N/A:P': [4.1, 4.9, 5.1],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:P/A:C': [6.8, 9.5, 3.9],
  'CVSS:2.0/AV:A/AC:H/Au:N/C:P/I:P/A:N': [3.2, 4.9, 3.2],
  'CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:N/A:P': [5.6, 7.8, 3.9],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:N/I:C/A:P': [7.5, 7.8, 8],
  'CVSS:2.0/AV:A/AC:L/Au:M/C:P/I:P/A:P': [4.7, 6.4, 4.1],
  // synthetic test data with temporal and environmental metrics random values
  'CVSS:2.0/AV:N/AC:L/Au:S/C:C/I:C/A:C/E:F/RL:ND/RC:ND/CDP:N/TD:L/CR:H/IR:M/AR:ND':
    [9, 10, 8, 8.5, 2.2],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N/E:U/RL:U/RC:C/CDP:ND/TD:N/CR:L/IR:ND/AR:L':
    [5, 2.9, 10, 4.3, 0],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:N/E:U/RL:W/RC:ND/CDP:N/TD:ND/CR:L/IR:M/AR:L':
    [6.4, 4.9, 10, 5.2, 4.6],
  'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:TF/RC:UR/CDP:L/TD:M/CR:M/IR:ND/AR:M':
    [7.5, 6.4, 10, 5.8, 4.7],
  'CVSS:2.0/AV:N/AC:L/Au:S/C:P/I:P/A:P/E:ND/RL:ND/RC:UR/CDP:H/TD:ND/CR:M/IR:H/AR:L':
    [6.5, 6.4, 8, 6.2, 8.2],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C/CDP:MH/TD:M/CR:H/IR:M/AR:M':
    [7.1, 6.9, 8.6, 5.6, 5.5],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:P/A:N/E:ND/RL:W/RC:UR/CDP:H/TD:H/CR:ND/IR:H/AR:L':
    [4.3, 2.9, 8.6, 3.9, 7.4],
  'CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:N/A:P/E:U/RL:U/RC:UR/CDP:MH/TD:H/CR:H/IR:H/AR:ND':
    [5.8, 4.9, 8.6, 4.7, 7.1],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:N/I:P/A:N/E:H/RL:ND/RC:C/CDP:MH/TD:N/CR:M/IR:ND/AR:ND':
    [3.5, 2.9, 6.8, 3.5, 0],
  'CVSS:2.0/AV:N/AC:M/Au:S/C:P/I:P/A:P/E:ND/RL:OF/RC:UR/CDP:LM/TD:ND/CR:H/IR:H/AR:H':
    [6, 6.4, 6.8, 5, 7.2]
};

describe('CVSS v2 Calculator', () => {
  describe('Calculate correctly base score', () => {
    Object.entries(cvssTests).map((entry) => {
      const cvss = entry[0];
      const baseScore = entry[1][0];
      it(`should calculate a score of ${baseScore} for ${cvss}`, () => {
        const res = new CvssV2Calculator().calculate(cvss);
        expect(res.baseScore).to.equal(baseScore);
      });
    });
  });

  describe('Calculate correctly impact', () => {
    Object.entries(cvssTests).map((entry) => {
      const cvss = entry[0];
      const impact = entry[1][1];
      it(`should calculate impact of ${impact} for ${cvss}`, () => {
        const res = new CvssV2Calculator().calculate(cvss);
        expect(res.baseImpact).to.equal(impact);
      });
    });
  });

  describe('Calculate correctly exploitability', () => {
    Object.entries(cvssTests).map((entry) => {
      const cvss = entry[0];
      const exploitability = entry[1][2];
      it(`should calculate exploitability of ${exploitability} for ${cvss}`, () => {
        const res = new CvssV2Calculator().calculate(cvss);
        expect(res.baseExploitability).to.equal(exploitability);
      });
    });
  });

  describe('Calculate correctly temporal score', () => {
    Object.entries(cvssTests)
      .filter((entry) => entry[1][3] !== undefined)
      .map((entry) => {
        const cvss = entry[0];
        const temporalScore = entry[1][3];
        it(`should calculate a score of ${temporalScore} for ${cvss}`, () => {
          const res = new CvssV2Calculator().calculate(cvss);
          expect(res.temporalScore).to.equal(temporalScore);
        });
      });
  });

  describe('Calculate correctly environmental score', () => {
    Object.entries(cvssTests)
      .filter((entry) => entry[1][4] !== undefined)
      .map((entry) => {
        const cvss = entry[0];
        const environmentalScore = entry[1][4];
        it(`should calculate a score of ${environmentalScore} for ${cvss}`, () => {
          const res = new CvssV2Calculator().calculate(cvss);
          expect(res.environmentalScore).to.equal(environmentalScore);
        });
      });
  });
});
