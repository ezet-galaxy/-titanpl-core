/**
 * tests/cookies.test.js
 * 
 * Tests for the cookies module
 * Pure JS API - no mocks required
 */
import { describe, it, expect } from 'vitest';
import { cookies } from '../index.js';

describe('cookies', () => {
    describe('get()', () => {
        it('should extract cookie from request', () => {
            const req = {
                headers: {
                    cookie: 'session=abc123; user=john'
                }
            };
            
            expect(cookies.get(req, 'session')).toBe('abc123');
            expect(cookies.get(req, 'user')).toBe('john');
        });

        it('should return null if cookie does not exist', () => {
            const req = {
                headers: {
                    cookie: 'session=abc123'
                }
            };
            
            expect(cookies.get(req, 'nonexistent')).toBeNull();
        });

        it('should return null if no headers', () => {
            expect(cookies.get({}, 'session')).toBeNull();
            expect(cookies.get({ headers: {} }, 'session')).toBeNull();
        });

        it('should return null if req is null/undefined', () => {
            expect(cookies.get(null, 'session')).toBeNull();
            expect(cookies.get(undefined, 'session')).toBeNull();
        });

        it('should handle cookie at start of string', () => {
            const req = {
                headers: { cookie: 'first=value; second=other' }
            };
            
            expect(cookies.get(req, 'first')).toBe('value');
        });

        it('should handle values with special characters', () => {
            const req = {
                headers: { cookie: 'token=eyJhbGciOiJIUzI1NiJ9.test' }
            };
            
            expect(cookies.get(req, 'token')).toBe('eyJhbGciOiJIUzI1NiJ9.test');
        });
    });

    describe('set()', () => {
        it('should set basic cookie', () => {
            const res = {};
            cookies.set(res, 'session', 'abc123');
            
            expect(res.headers['Set-Cookie']).toBe('session=abc123');
        });

        it('should set cookie with options', () => {
            const res = {};
            cookies.set(res, 'auth', 'token123', {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 3600,
                path: '/'
            });
            
            const cookie = res.headers['Set-Cookie'];
            expect(cookie).toContain('auth=token123');
            expect(cookie).toContain('HttpOnly');
            expect(cookie).toContain('Secure');
            expect(cookie).toContain('SameSite=Strict');
            expect(cookie).toContain('Max-Age=3600');
            expect(cookie).toContain('Path=/');
        });

        it('should handle multiple cookies', () => {
            const res = {};
            cookies.set(res, 'first', 'value1');
            cookies.set(res, 'second', 'value2');
            
            expect(Array.isArray(res.headers['Set-Cookie'])).toBe(true);
            expect(res.headers['Set-Cookie']).toHaveLength(2);
        });

        it('should not fail if res is null', () => {
            expect(() => cookies.set(null, 'test', 'value')).not.toThrow();
        });

        it('should create headers if they do not exist', () => {
            const res = {};
            cookies.set(res, 'new', 'cookie');
            
            expect(res.headers).toBeDefined();
            expect(res.headers['Set-Cookie']).toBe('new=cookie');
        });
    });

    describe('delete()', () => {
        it.skip('should delete cookie by setting empty value', () => {
            const res = {};
            cookies.delete(res, 'session');
            
            expect(res.headers['Set-Cookie']).toContain('session=');
        });
    });
});
