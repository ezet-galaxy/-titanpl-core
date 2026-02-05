/**
 * tests/setup.js
 * 
 * Emulates Rust native functions for testing.
 * Equivalent to what @t8n/micro-gravity/setup would do.
 * 
 * MOCKED:
 * - DB (PostgreSQL connection) - No way to test without a real DB
 * 
 * EMULATED (JS implementation that simulates Rust behavior):
 * - fs_* (uses Node.js fs)
 * - crypto_* (uses Node.js crypto)
 * - ls_* (uses in-memory Map)
 * - session_* (uses in-memory Map)
 * - os_*, net_*, proc_*, time_*, path_cwd
 */

import { vi } from 'vitest';
import * as nodeFs from 'node:fs';
import * as nodePath from 'node:path';
import * as nodeCrypto from 'node:crypto';
import * as nodeOs from 'node:os';

// In-memory storage for ls and session
const localStorage = new Map();
const sessionStorage = new Map();

// Initialize global `t` object with native functions
globalThis.t = globalThis.t || {};
globalThis.t["@titanpl/core"] = globalThis.t["@titanpl/core"] || {};
globalThis.t.native = globalThis.t.native || {};
globalThis.t.core = globalThis.t.core || {};

const ext = globalThis.t["@titanpl/core"];

// ============================================
// FILE SYSTEM - Emulation using Node.js fs
// ============================================

ext.fs_read_file = (path) => {
    try {
        return nodeFs.readFileSync(path, 'utf-8');
    } catch (e) {
        return `ERROR: ${e.message}`;
    }
};

ext.fs_write_file = (path, content) => {
    nodeFs.writeFileSync(path, content, 'utf-8');
};

ext.fs_readdir = (path) => {
    try {
        return JSON.stringify(nodeFs.readdirSync(path));
    } catch {
        return '[]';
    }
};

ext.fs_mkdir = (path) => {
    nodeFs.mkdirSync(path, { recursive: true });
};

ext.fs_exists = (path) => {
    return nodeFs.existsSync(path);
};

ext.fs_stat = (path) => {
    try {
        const stat = nodeFs.statSync(path);
        return JSON.stringify({
            size: stat.size,
            isFile: stat.isFile(),
            isDir: stat.isDirectory(),
            modified: stat.mtimeMs
        });
    } catch {
        return '{}';
    }
};

ext.fs_remove = (path) => {
    try {
        const stat = nodeFs.statSync(path);
        if (stat.isDirectory()) {
            nodeFs.rmSync(path, { recursive: true });
        } else {
            nodeFs.unlinkSync(path);
        }
    } catch { }
};

ext.path_cwd = () => process.cwd();

// ============================================
// CRYPTO - Emulation using Node.js crypto
// ============================================

ext.crypto_hash = (algo, data) => {
    try {
        const hash = nodeCrypto.createHash(algo);
        hash.update(data);
        return hash.digest('hex');
    } catch (e) {
        return `ERROR: ${e.message}`;
    }
};

ext.crypto_random_bytes = (size) => {
    return nodeCrypto.randomBytes(size).toString('hex');
};

ext.crypto_uuid = () => {
    return nodeCrypto.randomUUID();
};

ext.crypto_encrypt = (algo, jsonArgs) => {
    try {
        const { key, plaintext } = JSON.parse(jsonArgs);
        const keyBuffer = Buffer.alloc(32);
        Buffer.from(key).copy(keyBuffer);
        const iv = nodeCrypto.randomBytes(12);
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        return iv.toString('hex') + ':' + authTag + ':' + encrypted;
    } catch (e) {
        return `ERROR: ${e.message}`;
    }
};

ext.crypto_decrypt = (algo, jsonArgs) => {
    try {
        const { key, ciphertext } = JSON.parse(jsonArgs);
        const [ivHex, authTagHex, encrypted] = ciphertext.split(':');
        const keyBuffer = Buffer.alloc(32);
        Buffer.from(key).copy(keyBuffer);
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        return `ERROR: ${e.message}`;
    }
};

ext.crypto_hash_keyed = (algo, jsonArgs) => {
    try {
        const { key, message } = JSON.parse(jsonArgs);
        const hmac = nodeCrypto.createHmac(algo === 'sha256' ? 'sha256' : 'sha512', key);
        hmac.update(message);
        return hmac.digest('hex');
    } catch (e) {
        return `ERROR: ${e.message}`;
    }
};

ext.crypto_compare = (a, b) => {
    return nodeCrypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
};

// ============================================
// LOCAL STORAGE - In-memory emulation
// ============================================

ext.ls_get = (key) => {
    return localStorage.get(key) || '';
};

ext.ls_set = (key, value) => {
    localStorage.set(key, value);
};

ext.ls_remove = (key) => {
    localStorage.delete(key);
};

ext.ls_clear = () => {
    localStorage.clear();
};

ext.ls_keys = () => {
    return JSON.stringify([...localStorage.keys()]);
};

// Simplified V8 serialization (uses JSON as fallback)
ext.serialize = (value) => {
    try {
        const json = JSON.stringify(value);
        return new TextEncoder().encode(json);
    } catch {
        return null;
    }
};

ext.deserialize = (bytes) => {
    try {
        const json = new TextDecoder().decode(bytes);
        return JSON.parse(json);
    } catch {
        return null;
    }
};

// ============================================
// SESSION - In-memory emulation
// ============================================

ext.session_get = (sid, key) => {
    return sessionStorage.get(`${sid}:${key}`) || '';
};

ext.session_set = (sid, jsonArgs) => {
    const { key, value } = JSON.parse(jsonArgs);
    sessionStorage.set(`${sid}:${key}`, value);
};

ext.session_delete = (sid, key) => {
    sessionStorage.delete(`${sid}:${key}`);
};

ext.session_clear = (sid) => {
    for (const key of sessionStorage.keys()) {
        if (key.startsWith(`${sid}:`)) {
            sessionStorage.delete(key);
        }
    }
};

// ============================================
// OS - Emulation using Node.js os
// ============================================

ext.os_info = () => {
    return JSON.stringify({
        platform: nodeOs.platform(),
        cpus: nodeOs.cpus().length,
        totalMemory: nodeOs.totalmem(),
        freeMemory: nodeOs.freemem(),
        tmpdir: nodeOs.tmpdir()
    });
};

// ============================================
// NET - Basic emulation
// ============================================

ext.net_resolve = (hostname) => {
    return JSON.stringify(['127.0.0.1']);
};

ext.net_ip = () => {
    const interfaces = nodeOs.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return '127.0.0.1';
};

// ============================================
// PROC - Basic emulation
// ============================================

ext.proc_info = () => {
    return JSON.stringify({
        pid: process.pid,
        uptime: process.uptime()
    });
};

ext.proc_run = (jsonArgs) => {
    return JSON.stringify({ ok: false, error: 'Disabled in tests' });
};

ext.proc_kill = (pid) => {
    return false;
};

ext.proc_list = () => {
    return JSON.stringify([]);
};

// ============================================
// TIME
// ============================================

ext.time_sleep = (ms) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { }
};

// ============================================
// DATABASE - MOCK (only real mock)
// ============================================

globalThis.t.db = {
    connect: vi.fn().mockReturnValue({
        query: vi.fn().mockResolvedValue({ rows: [] }),
        execute: vi.fn().mockResolvedValue({ rowCount: 0 }),
        close: vi.fn()
    })
};

// ============================================
// Helpers to clear state between tests
// ============================================

export function clearStorage() {
    localStorage.clear();
    sessionStorage.clear();
}

import { beforeEach } from 'vitest';

beforeEach(() => {
    clearStorage();
});
