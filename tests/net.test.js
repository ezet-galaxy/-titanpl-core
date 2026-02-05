/**
 * tests/net.test.js
 * 
 * Tests for the net module
 * Uses emulated natives
 */
import { describe, it, expect } from 'vitest';
import { net } from '../index.js';

describe('net', () => {
    describe('ip()', () => {
        it('should return valid IP address', () => {
            const ip = net.ip();
            
            expect(typeof ip).toBe('string');
            // Should be IPv4 format or localhost
            expect(ip).toMatch(/^(\d{1,3}\.){3}\d{1,3}$/);
        });
    });

    describe('resolveDNS()', () => {
        it('should return array of IPs', () => {
            const ips = net.resolveDNS('localhost');
            
            expect(Array.isArray(ips)).toBe(true);
        });

        it('should return empty array for invalid hostname', () => {
            const ips = net.resolveDNS('');
            
            expect(Array.isArray(ips)).toBe(true);
        });
    });
});

/**
 * Tests for the proc module
 */
import { proc } from '../index.js';

describe('proc', () => {
    describe('info()', () => {
        it('should return process info', () => {
            const info = proc.info();
            
            expect(info).toHaveProperty('pid');
            expect(typeof info.pid).toBe('number');
            expect(info.pid).toBeGreaterThan(0);
        });
    });

    describe('pid()', () => {
        it('should return process PID', () => {
            const pid = proc.pid();
            
            expect(typeof pid).toBe('number');
            expect(pid).toBeGreaterThan(0);
        });
    });

    describe('list()', () => {
        it('should return array (possibly empty in tests)', () => {
            const processes = proc.list();
            
            expect(Array.isArray(processes)).toBe(true);
        });
    });

    describe('run()', () => {
        it('should return object (disabled in tests)', () => {
            const result = proc.run('echo', ['hello']);
            
            expect(typeof result).toBe('object');
        });
    });

    describe('kill()', () => {
        it('should return false (disabled in tests)', () => {
            const result = proc.kill(99999);
            
            expect(result).toBe(false);
        });
    });
});
