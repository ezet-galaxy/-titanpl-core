/**
 * tests/time.test.js
 * 
 * Tests for the time module
 * time.now() - Pure JS (Date.now())
 * time.sleep() - Native emulated
 */
import { describe, it, expect } from 'vitest';
import { time } from '../index.js';

describe('time', () => {
    describe('now()', () => {
        it('should return current timestamp', () => {
            const before = Date.now();
            const result = time.now();
            const after = Date.now();
            
            expect(result).toBeGreaterThanOrEqual(before);
            expect(result).toBeLessThanOrEqual(after);
        });

        it('should return number', () => {
            expect(typeof time.now()).toBe('number');
        });

        it('should increment over time', async () => {
            const first = time.now();
            await new Promise(r => setTimeout(r, 10));
            const second = time.now();
            
            expect(second).toBeGreaterThan(first);
        });
    });

    describe('sleep()', () => {
        it('should pause execution', () => {
            const start = Date.now();
            time.sleep(50);
            const elapsed = Date.now() - start;
            
            // Should have passed at least 40ms (margin of error)
            expect(elapsed).toBeGreaterThanOrEqual(40);
        });

        it('should accept small values', () => {
            expect(() => time.sleep(1)).not.toThrow();
        });

        it('should handle 0ms', () => {
            const start = Date.now();
            time.sleep(0);
            const elapsed = Date.now() - start;
            
            expect(elapsed).toBeLessThan(100);
        });
    });
});
