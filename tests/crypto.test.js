/**
 * tests/crypto.test.js
 * 
 * Tests for the crypto module
 * Uses emulated natives wrapping Node.js crypto
 */
import { describe, it, expect } from 'vitest';
import { crypto } from '../index.js';

describe('crypto', () => {
    describe('hash()', () => {
        it('should generate SHA256 hash', () => {
            const hash = crypto.hash('sha256', 'hello');
            
            expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
        });

        it('should generate SHA512 hash', () => {
            const hash = crypto.hash('sha512', 'hello');
            
            expect(hash).toHaveLength(128); // SHA512 = 64 bytes = 128 hex chars
            expect(hash).toMatch(/^[a-f0-9]+$/);
        });

        it('should return different hashes for different inputs', () => {
            const hash1 = crypto.hash('sha256', 'hello');
            const hash2 = crypto.hash('sha256', 'world');
            
            expect(hash1).not.toBe(hash2);
        });

        it('should return same hash for same input', () => {
            const hash1 = crypto.hash('sha256', 'consistent');
            const hash2 = crypto.hash('sha256', 'consistent');
            
            expect(hash1).toBe(hash2);
        });
    });

    describe('randomBytes()', () => {
        it('should generate random bytes in hex', () => {
            const bytes = crypto.randomBytes(16);
            
            expect(bytes).toHaveLength(32); // 16 bytes = 32 hex chars
            expect(bytes).toMatch(/^[a-f0-9]+$/);
        });

        it('should generate different values each time', () => {
            const bytes1 = crypto.randomBytes(16);
            const bytes2 = crypto.randomBytes(16);
            
            expect(bytes1).not.toBe(bytes2);
        });

        it('should respect specified size', () => {
            expect(crypto.randomBytes(8)).toHaveLength(16);
            expect(crypto.randomBytes(32)).toHaveLength(64);
        });
    });

    describe('uuid()', () => {
        it('should generate valid UUID v4', () => {
            const uuid = crypto.uuid();
            
            expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
        });

        it('should generate unique UUIDs', () => {
            const uuids = new Set();
            for (let i = 0; i < 100; i++) {
                uuids.add(crypto.uuid());
            }
            
            expect(uuids.size).toBe(100);
        });
    });

    describe('encrypt() and decrypt()', () => {
        it('should encrypt and decrypt text', () => {
            const key = '12345678901234567890123456789012'; // 32 bytes
            const plaintext = 'Secret message';
            
            const encrypted = crypto.encrypt('aes-256-gcm', key, plaintext);
            const decrypted = crypto.decrypt('aes-256-gcm', key, encrypted);
            
            expect(decrypted).toBe(plaintext);
        });

        it('should generate different ciphertexts for same plaintext', () => {
            const key = '12345678901234567890123456789012';
            const plaintext = 'Same message';
            
            const encrypted1 = crypto.encrypt('aes-256-gcm', key, plaintext);
            const encrypted2 = crypto.encrypt('aes-256-gcm', key, plaintext);
            
            // Due to random IV, they should be different
            expect(encrypted1).not.toBe(encrypted2);
        });

        it('should handle empty text', () => {
            const key = '12345678901234567890123456789012';
            
            const encrypted = crypto.encrypt('aes-256-gcm', key, '');
            const decrypted = crypto.decrypt('aes-256-gcm', key, encrypted);
            
            expect(decrypted).toBe('');
        });
    });

    describe('compare()', () => {
        it('should return true for equal strings', () => {
            expect(crypto.compare('abc', 'abc')).toBe(true);
        });

        it('should return false for different strings', () => {
            expect(crypto.compare('abc', 'def')).toBe(false);
        });
    });

    describe('hashKeyed()', () => {
        it('should generate HMAC-SHA256', () => {
            const hmac = crypto.hashKeyed('sha256', 'secret-key', 'message');
            
            expect(hmac).toHaveLength(64); // SHA256 = 32 bytes = 64 hex
            expect(hmac).toMatch(/^[a-f0-9]+$/);
        });

        it('should generate different HMACs with different keys', () => {
            const hmac1 = crypto.hashKeyed('sha256', 'key1', 'message');
            const hmac2 = crypto.hashKeyed('sha256', 'key2', 'message');
            
            expect(hmac1).not.toBe(hmac2);
        });

        it('should be consistent with same parameters', () => {
            const hmac1 = crypto.hashKeyed('sha256', 'key', 'msg');
            const hmac2 = crypto.hashKeyed('sha256', 'key', 'msg');
            
            expect(hmac1).toBe(hmac2);
        });
    });
});
