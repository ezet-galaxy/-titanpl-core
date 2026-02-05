/**
 * tests/path.test.js
 * 
 * Tests for the path module
 * Pure JS API - no mocks required
 */
import { describe, it, expect } from 'vitest';
import { path } from '../index.js';

describe('path', () => {
    describe('join()', () => {
        it('should join path segments', () => {
            expect(path.join('a', 'b', 'c')).toBe('a/b/c');
        });

        it('should normalize duplicate separators', () => {
            expect(path.join('a/', '/b/', '/c')).toBe('a/b/c');
        });

        it('should convert backslashes to forward slashes', () => {
            expect(path.join('a\\b', 'c\\d')).toBe('a/b/c/d');
        });

        it('should filter falsy values', () => {
            expect(path.join('a', null, 'b', undefined, 'c')).toBe('a/b/c');
        });

        it('should handle single segment', () => {
            expect(path.join('single')).toBe('single');
        });

        it('should handle absolute paths', () => {
            expect(path.join('/root', 'sub', 'file.txt')).toBe('/root/sub/file.txt');
        });
    });

    describe('dirname()', () => {
        it('should return parent directory', () => {
            expect(path.dirname('/home/user/file.txt')).toBe('/home/user');
        });

        it('should return "." for file without directory', () => {
            expect(path.dirname('file.txt')).toBe('.');
        });

        it('should handle paths with multiple levels', () => {
            expect(path.dirname('a/b/c/d.js')).toBe('a/b/c');
        });
    });

    describe('basename()', () => {
        it('should return filename', () => {
            expect(path.basename('/home/user/file.txt')).toBe('file.txt');
        });

        it('should return name for simple path', () => {
            expect(path.basename('file.txt')).toBe('file.txt');
        });

        it('should handle directories', () => {
            expect(path.basename('/home/user/')).toBe('');
            expect(path.basename('/home/user')).toBe('user');
        });
    });

    describe('extname()', () => {
        it('should return extension with dot', () => {
            expect(path.extname('file.txt')).toBe('.txt');
        });

        it('should return last extension', () => {
            expect(path.extname('archive.tar.gz')).toBe('.gz');
        });

        it('should return empty if no extension', () => {
            expect(path.extname('noextension')).toBe('');
        });

        it('should handle hidden files', () => {
            expect(path.extname('.gitignore')).toBe('');
        });

        it('should handle full paths', () => {
            expect(path.extname('/path/to/file.json')).toBe('.json');
        });
    });

    describe('resolve()', () => {
        it('should return absolute paths unchanged', () => {
            expect(path.resolve('/absolute/path')).toBe('/absolute/path');
        });

        it('should join multiple segments', () => {
            const result = path.resolve('a', 'b', 'c');
            expect(result).toContain('a/b/c');
        });

        it('should handle Windows paths', () => {
            expect(path.resolve('C:/Users/test')).toBe('C:/Users/test');
        });
    });
});
