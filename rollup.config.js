import typescript from 'rollup-plugin-typescript2';

const pkg = require('./package.json');

export default {
  input: `src/index.ts`,
  output: [
    { file: pkg.main, name: 'cvss', format: 'umd', sourcemap: false },
    { file: './dist/bundle.es.js', format: 'es', sourcemap: false }
  ],
  // Indicate here external modules you don't wanna include in your bundle (i.e.: 'lodash')
  external: [],
  watch: {
    include: 'src/**'
  },
  plugins: [
    // Compile TypeScript files
    typescript({ useTsconfigDeclarationDir: true })
  ]
};
