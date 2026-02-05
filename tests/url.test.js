/**
 * tests/url.test.js
 * 
 * Tests for the url module
 * Pure JS API - uses native URL and URLSearchParams
 */
import { describe, it, expect } from 'vitest';
import { url } from '../index.js';

describe('url', () => {
    describe('parse()', () => {
        it('should parse complete URL', () => {
            const parsed = url.parse('https://example.com:8080/path?query=value#hash');
            
            expect(parsed.protocol).toBe('https:');
            expect(parsed.hostname).toBe('example.com');
            expect(parsed.port).toBe('8080');
            expect(parsed.pathname).toBe('/path');
            expect(parsed.search).toBe('?query=value');
            expect(parsed.hash).toBe('#hash');
        });

        it('should parse simple URL', () => {
            const parsed = url.parse('https://example.com');
            
            expect(parsed.hostname).toBe('example.com');
            expect(parsed.pathname).toBe('/');
        });

        it('should return null for invalid URL', () => {
            expect(url.parse('not-a-url')).toBeNull();
            expect(url.parse('')).toBeNull();
        });

        it('should handle query params', () => {
            const parsed = url.parse('https://api.example.com/search?q=test&page=1');
            
            expect(parsed.searchParams.get('q')).toBe('test');
            expect(parsed.searchParams.get('page')).toBe('1');
        });

        it('should handle URLs with authentication', () => {
            const parsed = url.parse('https://user:pass@example.com/path');
            
            expect(parsed.username).toBe('user');
            expect(parsed.password).toBe('pass');
        });
    });

    describe('SearchParams', () => {
        it('should create URLSearchParams instance', () => {
            const params = new url.SearchParams('foo=bar&baz=qux');
            
            expect(params.get('foo')).toBe('bar');
            expect(params.get('baz')).toBe('qux');
        });

        it('should serialize to string', () => {
            const params = new url.SearchParams();
            params.append('key', 'value');
            params.append('another', 'test');
            
            expect(params.toString()).toContain('key=value');
            expect(params.toString()).toContain('another=test');
        });

        it('should handle encoded values', () => {
            const params = new url.SearchParams();
            params.set('message', 'Hello World!');
            
            expect(params.toString()).toContain('Hello');
        });

        it('should iterate over entries', () => {
            const params = new url.SearchParams('a=1&b=2&c=3');
            const entries = [...params.entries()];
            
            expect(entries).toHaveLength(3);
            expect(entries[0]).toEqual(['a', '1']);
        });
    });
});
