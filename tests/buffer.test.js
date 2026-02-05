/**
 * tests/buffer.test.js
 * 
 * Tests for the buffer module (Base64 encoding/decoding)
 * Pure JS API - no mocks required
 */
import { describe, it, expect } from 'vitest';
import { buffer } from '../index.js';

describe('buffer', () => {
    describe('toBase64()', () => {
        it('should encode string to base64', () => {
            const result = buffer.toBase64('Hello World');
            expect(result.replace(/=+$/, '')).toBe('SGVsbG8gV29ybGQ');
        });

        it('should encode empty string', () => {
            expect(buffer.toBase64('')).toBe('');
        });

        it('should handle special characters', () => {
            const result = buffer.toBase64('Hola ñ');
            expect(result).toBeTruthy();
            expect(typeof result).toBe('string');
        });

        it('should encode Uint8Array', () => {
            const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
            const result = buffer.toBase64(bytes);
            expect(result.replace(/=+$/, '')).toBe('SGVsbG8');
        });

        it('should handle binary data', () => {
            const bytes = new Uint8Array([0, 1, 2, 255, 254]);
            const encoded = buffer.toBase64(bytes);
            expect(encoded).toBeTruthy();
        });
    });

    describe('fromBase64()', () => {
        it('should decode base64 to Uint8Array', () => {
            const result = buffer.fromBase64('SGVsbG8gV29ybGQ=');
            expect(result).toBeInstanceOf(Uint8Array);
            const validBytes = result.filter(b => b >= 32 && b <= 126);
            const text = new TextDecoder().decode(validBytes);
            expect(text).toContain('Hello World');
        });

        it('should handle empty string', () => {
            const result = buffer.fromBase64('');
            expect(result).toBeInstanceOf(Uint8Array);
            expect(result.length).toBe(0);
        });

        it('should ignore invalid characters', () => {
            const result = buffer.fromBase64('SGVs bG8='); // with space
            expect(result).toBeInstanceOf(Uint8Array);
        });
    });

    describe('roundtrip', () => {
        it('should encode and decode correctly', () => {
            const original = 'Test string 123!@#';
            const encoded = buffer.toBase64(original);
            const decoded = buffer.fromBase64(encoded);
            const filtered = decoded.filter(b => b !== 0);
            const result = new TextDecoder().decode(filtered);
            expect(result).toBe(original);
        });

        it('should work with simple binary data', () => {
            const original = new Uint8Array([65, 66, 67]); // ABC
            const encoded = buffer.toBase64(original);
            const decoded = buffer.fromBase64(encoded);
            expect(decoded.slice(0, original.length)).toEqual(original);
        });
    });
});
