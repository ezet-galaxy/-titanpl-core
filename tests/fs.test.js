/**
 * tests/fs.test.js
 * 
 * Tests for the fs module
 * Uses emulated natives wrapping Node.js fs
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { fs, path } from '../index.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('fs', () => {
    let testDir;

    beforeEach(() => {
        testDir = mkdtempSync(join(tmpdir(), 'titanpl-test-'));
    });

    afterEach(() => {
        try {
            rmSync(testDir, { recursive: true, force: true });
        } catch { }
    });

    describe('writeFile() and readFile()', () => {
        it('should write and read text file', () => {
            const filePath = join(testDir, 'test.txt');
            const content = 'Hello, Titan!';
            
            fs.writeFile(filePath, content);
            const result = fs.readFile(filePath);
            
            expect(result).toBe(content);
        });

        it('should handle multiline content', () => {
            const filePath = join(testDir, 'multiline.txt');
            const content = 'Line 1\nLine 2\nLine 3';
            
            fs.writeFile(filePath, content);
            const result = fs.readFile(filePath);
            
            expect(result).toBe(content);
        });

        it('should overwrite existing file', () => {
            const filePath = join(testDir, 'overwrite.txt');
            
            fs.writeFile(filePath, 'Original');
            fs.writeFile(filePath, 'Updated');
            
            expect(fs.readFile(filePath)).toBe('Updated');
        });

        it('should handle JSON', () => {
            const filePath = join(testDir, 'data.json');
            const data = { name: 'Test', value: 42 };
            
            fs.writeFile(filePath, JSON.stringify(data));
            const result = JSON.parse(fs.readFile(filePath));
            
            expect(result).toEqual(data);
        });
    });

    describe('exists()', () => {
        it('should return true for existing file', () => {
            const filePath = join(testDir, 'exists.txt');
            fs.writeFile(filePath, 'test');
            
            expect(fs.exists(filePath)).toBe(true);
        });

        it('should return false for non-existing file', () => {
            expect(fs.exists(join(testDir, 'nonexistent.txt'))).toBe(false);
        });

        it('should work with directories', () => {
            expect(fs.exists(testDir)).toBe(true);
        });
    });

    describe('mkdir()', () => {
        it('should create directory', () => {
            const dirPath = join(testDir, 'newdir');
            
            fs.mkdir(dirPath);
            
            expect(fs.exists(dirPath)).toBe(true);
        });

        it('should create nested directories (recursive)', () => {
            const dirPath = join(testDir, 'a', 'b', 'c');
            
            fs.mkdir(dirPath);
            
            expect(fs.exists(dirPath)).toBe(true);
        });
    });

    describe('readdir()', () => {
        it('should list directory contents', () => {
            fs.writeFile(join(testDir, 'file1.txt'), 'a');
            fs.writeFile(join(testDir, 'file2.txt'), 'b');
            
            const files = fs.readdir(testDir);
            
            expect(files).toContain('file1.txt');
            expect(files).toContain('file2.txt');
        });

        it('should return empty array for empty directory', () => {
            const emptyDir = join(testDir, 'empty');
            fs.mkdir(emptyDir);
            
            const files = fs.readdir(emptyDir);
            
            expect(files).toEqual([]);
        });

        it('should return empty array if not exists', () => {
            const files = fs.readdir(join(testDir, 'nonexistent'));
            
            expect(files).toEqual([]);
        });
    });

    describe('stat()', () => {
        it('should return file stats', () => {
            const filePath = join(testDir, 'stat-test.txt');
            fs.writeFile(filePath, 'Hello World');
            
            const stat = fs.stat(filePath);
            
            expect(stat.isFile).toBe(true);
            expect(stat.isDir).toBe(false);
            expect(stat.size).toBeGreaterThan(0);
            expect(stat.modified).toBeGreaterThan(0);
        });

        it('should return directory stats', () => {
            const stat = fs.stat(testDir);
            
            expect(stat.isFile).toBe(false);
            expect(stat.isDir).toBe(true);
        });

        it('should return empty object if not exists', () => {
            const stat = fs.stat(join(testDir, 'nonexistent'));
            
            expect(stat).toEqual({});
        });
    });

    describe('remove()', () => {
        it('should remove file', () => {
            const filePath = join(testDir, 'to-delete.txt');
            fs.writeFile(filePath, 'delete me');
            
            expect(fs.exists(filePath)).toBe(true);
            fs.remove(filePath);
            expect(fs.exists(filePath)).toBe(false);
        });

        it('should remove directory with contents', () => {
            const dirPath = join(testDir, 'to-delete-dir');
            fs.mkdir(dirPath);
            fs.writeFile(join(dirPath, 'file.txt'), 'content');
            
            fs.remove(dirPath);
            
            expect(fs.exists(dirPath)).toBe(false);
        });
    });
});
