/**
 * tests/os.test.js
 * 
 * Tests for the os module
 * Uses emulated natives wrapping Node.js os
 */
import { describe, it, expect } from 'vitest';
import { os } from '../index.js';

describe('os', () => {
    describe('info()', () => {
        it('should return object with system info', () => {
            const info = os.info();
            
            expect(info).toHaveProperty('platform');
            expect(info).toHaveProperty('cpus');
            expect(info).toHaveProperty('totalMemory');
            expect(info).toHaveProperty('freeMemory');
        });

        it('should have valid values', () => {
            const info = os.info();
            
            expect(typeof info.platform).toBe('string');
            expect(info.cpus).toBeGreaterThan(0);
            expect(info.totalMemory).toBeGreaterThan(0);
            expect(info.freeMemory).toBeGreaterThanOrEqual(0);
        });
    });

    describe('platform()', () => {
        it('should return valid platform', () => {
            const platform = os.platform();
            
            expect(['linux', 'darwin', 'win32', 'freebsd', 'openbsd']).toContain(platform);
        });
    });

    describe('cpus()', () => {
        it('should return number of CPUs', () => {
            const cpus = os.cpus();
            
            expect(typeof cpus).toBe('number');
            expect(cpus).toBeGreaterThan(0);
        });
    });

    describe('totalMemory()', () => {
        it('should return total memory in bytes', () => {
            const total = os.totalMemory();
            
            expect(typeof total).toBe('number');
            expect(total).toBeGreaterThan(0);
        });
    });

    describe('freeMemory()', () => {
        it('should return free memory in bytes', () => {
            const free = os.freeMemory();
            
            expect(typeof free).toBe('number');
            expect(free).toBeGreaterThanOrEqual(0);
        });

        it('free memory should be less than or equal to total', () => {
            const total = os.totalMemory();
            const free = os.freeMemory();
            
            expect(free).toBeLessThanOrEqual(total);
        });
    });

    describe('tmpdir()', () => {
        it('should return temp directory', () => {
            const tmp = os.tmpdir();
            
            expect(typeof tmp).toBe('string');
            expect(tmp.length).toBeGreaterThan(0);
        });
    });
});
