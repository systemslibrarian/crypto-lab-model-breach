import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Unit tests live next to the crypto in src/. The Playwright accessibility
    // suite in e2e/ is a separate runner (npm run test:a11y) and must never be
    // collected by vitest.
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
