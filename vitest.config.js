// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        setupFiles: ['t8n-micro-gravity/setup'],
    }
});