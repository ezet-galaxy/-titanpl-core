/**
 * tests/response.test.js
 * 
 * Tests for the response module
 * Pure JS API - no mocks required
 */
import { describe, it, expect } from 'vitest';
import { response } from '../index.js';

describe('response', () => {
    describe('response()', () => {
        it('should create basic response', () => {
            const res = response({ status: 200, body: 'OK' });
            
            expect(res._isResponse).toBe(true);
            expect(res.status).toBe(200);
            expect(res.body).toBe('OK');
            expect(res.headers).toEqual({});
        });

        it('should use default values', () => {
            const res = response({});
            
            expect(res.status).toBe(200);
            expect(res.body).toBe('');
            expect(res.headers).toEqual({});
        });

        it('should include custom headers', () => {
            const res = response({
                status: 201,
                headers: { 'X-Custom': 'value' },
                body: 'Created'
            });
            
            expect(res.headers['X-Custom']).toBe('value');
        });
    });

    describe('response.json()', () => {
        it('should create JSON response', () => {
            const res = response.json({ message: 'Hello', count: 42 });
            
            expect(res._isResponse).toBe(true);
            expect(res.status).toBe(200);
            expect(res.headers['Content-Type']).toBe('application/json');
            expect(res.body).toBe('{"message":"Hello","count":42}');
        });

        it('should allow custom status', () => {
            const res = response.json({ error: 'Not found' }, { status: 404 });
            
            expect(res.status).toBe(404);
        });

        it('should serialize arrays', () => {
            const res = response.json([1, 2, 3]);
            
            expect(res.body).toBe('[1,2,3]');
        });

        it('should handle complex objects', () => {
            const data = {
                users: [{ id: 1, name: 'John' }],
                meta: { total: 1 }
            };
            const res = response.json(data);
            
            expect(JSON.parse(res.body)).toEqual(data);
        });
    });

    describe('response.text()', () => {
        it('should create plain text response', () => {
            const res = response.text('Hello World');
            
            expect(res._isResponse).toBe(true);
            expect(res.body).toBe('Hello World');
        });

        it('should convert numbers to string', () => {
            const res = response.text(42);
            
            expect(res.body).toBe('42');
        });
    });

    describe('response.html()', () => {
        it('should create HTML response', () => {
            const html = '<html><body>Hello</body></html>';
            const res = response.html(html);
            
            expect(res._isResponse).toBe(true);
            expect(res.headers['Content-Type']).toBe('text/html');
            expect(res.body).toBe(html);
        });

        it('should allow additional headers', () => {
            const res = response.html('<p>Test</p>', {
                headers: { 'X-Frame-Options': 'DENY' }
            });
            
            expect(res.headers['Content-Type']).toBe('text/html');
            expect(res.headers['X-Frame-Options']).toBe('DENY');
        });
    });

    describe('response.redirect()', () => {
        it('should create 302 redirect by default', () => {
            const res = response.redirect('/new-location');
            
            expect(res._isResponse).toBe(true);
            expect(res.status).toBe(302);
            expect(res.headers['Location']).toBe('/new-location');
        });

        it('should allow 301 permanent redirect', () => {
            const res = response.redirect('/permanent', 301);
            
            expect(res.status).toBe(301);
            expect(res.headers['Location']).toBe('/permanent');
        });

        it('should handle absolute URLs', () => {
            const res = response.redirect('https://example.com/path');
            
            expect(res.headers['Location']).toBe('https://example.com/path');
        });
    });

    describe('response.empty()', () => {
        it.skip('should create empty 204 response by default', () => {
            const res = response.empty();
            
            expect(res._isResponse).toBe(true);
            expect(res.status).toBe(204);
            expect(res.body).toBe('');
        });

        it.skip('should allow custom status', () => {
            const res = response.empty(202);
            
            expect(res.status).toBe(202);
        });
    });
});
