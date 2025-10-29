const { rollup } = require('rollup');
const { nodeResolve } = require('@rollup/plugin-node-resolve');

async function build() {
  const bundle = await rollup({
    input: 'src/nacf-sdk.js',
    plugins: [nodeResolve()]
  });

  await bundle.write({
    file: 'dist/nacf-sdk.js',
    format: 'umd',
    name: 'NACF'
  });

  await bundle.write({
    file: 'dist/nacf-sdk.mjs',
    format: 'es'
  });

  console.log('Build completed!');
}

build();