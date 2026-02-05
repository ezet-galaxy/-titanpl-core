/**
 * tests/session.test.js
 * 
 * Tests for the session module
 * Uses emulated natives with in-memory Map
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { session } from '../index.js';

describe('session', () => {
    const SESSION_ID = 'test-session-123';

    beforeEach(() => {
        // setup.js clears sessions before each test
    });

    describe('set() and get()', () => {
        it('should store and retrieve session value', () => {
            session.set(SESSION_ID, 'username', 'john');
            
            expect(session.get(SESSION_ID, 'username')).toBe('john');
        });

        it('should keep sessions separate by ID', () => {
            session.set('session-1', 'user', 'alice');
            session.set('session-2', 'user', 'bob');
            
            expect(session.get('session-1', 'user')).toBe('alice');
            expect(session.get('session-2', 'user')).toBe('bob');
        });

        it('should return empty for non-existing key', () => {
            expect(session.get(SESSION_ID, 'nonexistent')).toBe('');
        });

        it('should store multiple keys per session', () => {
            session.set(SESSION_ID, 'key1', 'value1');
            session.set(SESSION_ID, 'key2', 'value2');
            session.set(SESSION_ID, 'key3', 'value3');
            
            expect(session.get(SESSION_ID, 'key1')).toBe('value1');
            expect(session.get(SESSION_ID, 'key2')).toBe('value2');
            expect(session.get(SESSION_ID, 'key3')).toBe('value3');
        });
    });

    describe('delete()', () => {
        it('should delete specific key from session', () => {
            session.set(SESSION_ID, 'toDelete', 'value');
            session.set(SESSION_ID, 'toKeep', 'value');
            
            session.delete(SESSION_ID, 'toDelete');
            
            expect(session.get(SESSION_ID, 'toDelete')).toBe('');
            expect(session.get(SESSION_ID, 'toKeep')).toBe('value');
        });

        it('should not fail when deleting non-existing key', () => {
            expect(() => session.delete(SESSION_ID, 'nonexistent')).not.toThrow();
        });
    });

    describe('clear()', () => {
        it('should delete entire session', () => {
            session.set(SESSION_ID, 'key1', 'value1');
            session.set(SESSION_ID, 'key2', 'value2');
            
            session.clear(SESSION_ID);
            
            expect(session.get(SESSION_ID, 'key1')).toBe('');
            expect(session.get(SESSION_ID, 'key2')).toBe('');
        });

        it('should not affect other sessions', () => {
            session.set('session-1', 'data', 'one');
            session.set('session-2', 'data', 'two');
            
            session.clear('session-1');
            
            expect(session.get('session-1', 'data')).toBe('');
            expect(session.get('session-2', 'data')).toBe('two');
        });
    });

    describe('real-world use cases', () => {
        it('should handle auth token', () => {
            const authSession = 'auth-abc123';
            const token = 'eyJhbGciOiJIUzI1NiJ9.test';
            
            session.set(authSession, 'token', token);
            session.set(authSession, 'expires', '2025-12-31');
            
            expect(session.get(authSession, 'token')).toBe(token);
            expect(session.get(authSession, 'expires')).toBe('2025-12-31');
        });

        it('should handle shopping cart', () => {
            const cartSession = 'cart-xyz789';
            const cart = JSON.stringify([
                { id: 1, qty: 2 },
                { id: 2, qty: 1 }
            ]);
            
            session.set(cartSession, 'items', cart);
            
            const retrieved = JSON.parse(session.get(cartSession, 'items'));
            expect(retrieved).toHaveLength(2);
        });
    });
});
