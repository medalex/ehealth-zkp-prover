/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: '.',
  testMatch: ['**/test/**/*spec.ts'],
  // Groth16 proof generation is slow — allow generous per-test time.
  testTimeout: 180000,
};
