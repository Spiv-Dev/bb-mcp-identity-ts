import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 20_000,
    pool: 'forks',
    poolOptions: { forks: { minForks: 1, maxForks: 3 } },
  },
});
