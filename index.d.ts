// Type definitions for @titanpl/core
// Project: https://github.com/titanpl/core
// Definitions by: TitanPL Team
//
// This reference ensures global types (t.fs, t.response, etc.) are always
// loaded when this package is imported OR included via tsconfig "types".
/// <reference path="./globals.d.ts" />

// ==================== ESM Named Exports ====================
// These match the `export { ... }` block in the JS implementation.
// Usage: import { fs, crypto, path } from '@titanpl/core';

/** File System module */
export declare const fs: TitanCore.FileSystem;

/** Path manipulation module */
export declare const path: TitanCore.Path;

/** Cryptography module */
export declare const crypto: TitanCore.Crypto;

/** Operating System module */
export declare const os: TitanCore.OS;

/** Network module */
export declare const net: TitanCore.Net;

/** Process module */
export declare const proc: TitanCore.Process;

/** Time module */
export declare const time: TitanCore.Time;

/**
* URL API - Robust URL parsing and construction.
* 
* compliant URL parser that breaks down protocols, hostnames, and query parameters.
* 
* @use Parsing incoming request URLs, building outgoing fetch URLs.
*/
export declare const url: TitanCore.URLModule;



/** Buffer module */
export declare const buffer: TitanCore.BufferModule;

/**
* Local Storage API - High-performance in-memory key-value store.
* 
* **Performance:** ~150,000+ operations/sec.
* 
* - ⚡ RwLock<HashMap> implementation (~0.006ms per read)
* - 🚀 ~1000x faster than file-based storage
 * - 💾 In-memory only (volatile)
 * - 📦 **New:** Supports V8 Serialization (store Maps, Sets, Dates, etc.)
 * 
 * @use Perfect for caching frequently accessed data and complex objects within a single process.
 * @suggestion Use `setObject`/`getObject` for complex data structures to maintain types.
*/
export declare const ls: TitanCore.LocalStorage;

/** Session module */
export declare const session: TitanCore.Session;

/** Cookies module */
export declare const cookies: TitanCore.Cookies;

/** Response builder module */
export declare const response: TitanCore.ResponseModule;

/**
 * Core namespace - Unified access to all APIs
 */
export declare const core: TitanCore.Core;

/**
 * # Drift - Orchestration Engine
 * 
 * Revolutionary system for high-performance asynchronous operations using a **Deterministic Replay-based Suspension** model.
 * 
 * ## Mechanism
 * Drift utilizes a suspension model similar to **Algebraic Effects**. When a `drift()` operation is encountered, 
 * the runtime suspends the isolate, offloads the task to the background Tokio executor, and frees the isolate 
 * to handle other requests. Upon completion, the code is efficiently **re-played** with the result injected.
 * 
 * @param promise - The promise or expression to drift.
 * @returns The resolved value of the input promise.
 * 
 * @example
 * ```javascript
 * const resp = drift(t.fetch("http://api.titan.com"));
 * console.log(resp.body);
 * ```
 */
function drift<T>(promise: Promise<T> | T): T;

/**
 * Titan Core Global Namespace
 */
namespace TitanCore {
    /**
     * Core module containing all standard library APIs
     */
    interface Core {
        fs: FileSystem;
        path: Path;
        crypto: Crypto;
        os: OS;
        net: Net;
        proc: Process;
        time: Time;
        url: URLModule;
        buffer: BufferModule;
        ls: LocalStorage;
        session: Session;
        cookies: Cookies;
        response: ResponseModule;
    }

    // ==================== File System ====================

    /**
     * File System API - Native file operations backed by Rust
     */
    interface FileSystem {
        /**
         * Read file content as UTF-8 string.
         * @param path File path.
         */
        readFile(path: string): string;

        /**
         * Write string content to file.
         * @param path Target file path.
         * @param content String content to write.
         */
        writeFile(path: string, content: string): void;

        /**
         * List directory contents.
         * @param path Directory path.
         */
        readdir(path: string): string[];

        /**
         * Create a directory (recursive).
         * @param path Directory path to create.
         */
        mkdir(path: string): void;

        /**
         * Check if path exists.
         * @param path Path to check.
         */
        exists(path: string): boolean;

        /**
         * Get file statistics.
         * @param path Path to stat.
         * @returns Statistics object `{ type: "file" | "directory", size: number }`.
         */
        stat(path: string): Stats;

        /**
         * Remove file or directory (recursive).
         * @param path Path to remove.
         */
        remove(path: string): void;
    }

    /**
     * File/directory statistics
     */
    interface Stats {
        /** File size in bytes */
        size: number;
        /** True if path is a file */
        isFile: boolean;
        /** True if path is a directory */
        isDir: boolean;
        /** Last modified timestamp (milliseconds since epoch) */
        modified: number;
    }

    // ==================== Path ====================

    /**
     * Path API - Cross-platform path manipulation
     */
    interface Path {
        /**
         * Joins path segments using platform-specific separator
         * @param args - Path segments to join
         * @returns Joined path
         * @example
         * ```typescript
         * t.path.join('app', 'actions', 'test.js') // "app/actions/test.js"
         * ```
         */
        join(...args: string[]): string;

        /**
         * Resolves path segments to an absolute path
         * @param args - Path segments to resolve
         * @returns Absolute path
         */
        resolve(...args: string[]): string;

        /**
         * Returns the file extension including the dot
         * @param path - File path
         * @returns Extension (e.g., ".js", ".json") or empty string
         */
        extname(path: string): string;

        /**
         * Returns the directory name of a path
         * @param path - File or directory path
         * @returns Parent directory path
         */
        dirname(path: string): string;

        /**
         * Returns the last portion of a path (filename)
         * @param path - Path to extract basename from
         * @returns Filename or directory name
         */
        basename(path: string): string;
    }

    // ==================== Crypto ====================

    /**
     * Cryptography API - Hashing, encryption, and random generation
     */
    interface Crypto {
        /**
         * Hash data.
         * @param algorithm Algorithm to use: `sha256`, `sha512`, `md5`.
         * @param data Data to hash.
         */
        hash(algorithm: 'sha256' | 'sha512' | 'md5', data: string): string;

        /**
         * Generate random bytes as hex string.
         * @param size Number of bytes.
         */
        randomBytes(size: number): string;

        /**
         * Generate a UUID v4.
         */
        uuid(): string;

        /**
         * Constant-time comparison to prevent timing attacks.
         * @param hash The reference hash.
         * @param target The hash to compare against.
         */
        compare(hash: string, target: string): boolean;

        /**
         * AES-256-GCM Encrypt.
         * @param algorithm Encryption algorithm.
         * @param key 32-byte key.
         * @param plaintext Data to encrypt.
         * @returns Base64 encoded ciphertext.
         */
        encrypt(algorithm: string, key: string, plaintext: string): string;

        /**
         * AES-256-GCM Decrypt.
         * @param algorithm Decryption algorithm.
         * @param key Matching 32-byte key.
         * @param ciphertext Base64 encoded ciphertext.
         */
        decrypt(algorithm: string, key: string, ciphertext: string): string;

        /**
         * HMAC calculation.
         * @param algorithm `hmac-sha256` or `hmac-sha512`.
         * @param key Secret key.
         * @param message Message to sign.
         */
        hashKeyed(algorithm: 'hmac-sha256' | 'hmac-sha512', key: string, message: string): string;
    }

    // ==================== OS ====================

    /**
     * Operating System API - System information
     */
    interface OS {
        /** OS platform (e.g., `linux`, `windows`). */
        platform(): string;
        /** Number of CPU cores. */
        cpus(): number;
        /** Total system memory in bytes. */
        totalMemory(): number;
        /** Free system memory in bytes. */
        freeMemory(): number;
        /** Temporary directory path. */
        tmpdir(): string;
    }

    // ==================== Network ====================

    /**
     * Network API - DNS resolution and IP utilities
     */
    interface Net {
        /** Resolve hostname to IP addresses. */
        resolveDNS(hostname: string): string[];
        /** Get local IP address. */
        ip(): string;
        /** Ping (not fully implemented). */
        ping(host: string): boolean;
    }

    // ==================== Process ====================

    /**
     * Process API - Runtime process information
     */
    interface Process {
        /** Process ID. */
        pid(): number;
        /** System uptime in seconds. */
        uptime(): number;
        /** Memory usage statistics. */
        memory(): Record<string, any>;
        /**
         * Spawn a subprocess.
         * @param command The executable to run.
         * @param args Arguments to pass.
         * @returns Object containing the PID of the spawned process, e.g. `{ pid: 1234 }`.
         */
        run(command: string, args: string[], cwd?: string): { ok: boolean, pid: number, cwd: string };

        /**
         * Kill a process by PID.
         * @param pid Process ID to kill.
         * @returns True if the signal was sent successfully.
         */
        kill(pid: number): boolean;

        /**
         * List running processes.
         * @returns Array of process information objects.
         */
        list(): Array<{ pid: number, name: string, cmd: string, cpu?: number, memory?: number }>;
    }

    // ==================== Time ====================

    /**
     * Time API - Time utilities and delays
     */
    interface Time {
        /** Sleep for specified milliseconds. */
        sleep(ms: number): void;
        /** Current timestamp (ms). */
        now(): number;
        /** Current ISO timestamp. */
        timestamp(): string;
    }

    // ==================== URL ====================

    /**
     * URL API - URL parsing and manipulation
     */
    interface URLModule {
        /**
         * Parses a URL string into components
         * @param url - URL string to parse
         * @returns Parsed URL object
         */
        parse(url: string): UrlObject;

        /**
         * Formats a URL object into a string
         * @param urlObj - URL object to format
         * @returns URL string
         */
        format(urlObj: any): string;

        /**
         * URLSearchParams constructor
         */
        SearchParams: typeof TitanURLSearchParams;
    }

    /**
     * Parsed URL components
     */
    interface UrlObject {
        protocol: string;
        hostname: string;
        port: string;
        pathname: string;
        search: string;
        hash: string;
    }

    /**
     * URLSearchParams - Query string parsing and manipulation
     */
    class TitanURLSearchParams {
        constructor(init?: string | Record<string, string>);

        /**
         * Gets a query parameter value
         * @param key - Parameter name
         * @returns Parameter value or null
         */
        get(key: string): string | null;

        /**
         * Sets a query parameter
         * @param key - Parameter name
         * @param value - Parameter value
         */
        set(key: string, value: string): void;

        /**
         * Checks if parameter exists
         * @param key - Parameter name
         * @returns true if exists
         */
        has(key: string): boolean;

        /**
         * Deletes a query parameter
         * @param key - Parameter name
         */
        delete(key: string): void;

        /**
         * Converts to query string
         * @returns URL-encoded query string
         */
        toString(): string;

        /**
         * Returns all key-value pairs
         * @returns Array of [key, value] tuples
         */
        entries(): [string, string][];

        /**
         * Returns all parameter names
         * @returns Array of keys
         */
        keys(): string[];

        /**
         * Returns all parameter values
         * @returns Array of values
         */
        values(): string[];
    }

    // ==================== Buffer ====================

    /**
     * Buffer API - Binary data encoding and decoding
     */
    interface BufferModule {
        /** Decode Base64 string. */
        fromBase64(str: string): Uint8Array;
        /** Encode to Base64. */
        toBase64(bytes: Uint8Array | string): string;
        /** Decode Hex string. */
        fromHex(str: string): Uint8Array;
        /** Encode to Hex. */
        toHex(bytes: Uint8Array | string): string;
        /** Encode UTF-8 string to bytes. */
        fromUtf8(str: string): Uint8Array;
        /** Decode bytes to UTF-8 string. */
        toUtf8(bytes: Uint8Array): string;
    }

    // ==================== Local Storage ====================

    /**
     * Local Storage API - High-performance in-memory key-value store
     * 
     * **Implementation:** Native Rust RwLock<HashMap>
     * 
     * **Performance Benchmarks (10,000 operations):**
     * - 📖 Read: ~156,250 ops/sec (0.0064ms avg)
     * - ✍️ Write: ~89,286 ops/sec (0.0112ms avg)
     * - 🔄 Mixed: ~125,000 ops/sec (0.008ms avg)
     * 
     * **Characteristics:**
     * - ⚡ ~1000x faster than file-based storage
     * - 💾 In-memory only (data lost on server restart)
     * - 🔒 Thread-safe with RwLock (multiple readers, single writer)
     * - 🚫 Not shared across multiple processes
     * 
     * **Use Cases:**
     * - Request-scoped state sharing
     * - Temporary caching within a process
     * - High-frequency read/write operations
     * 
     * @example
     * ```typescript
     * // Store user data temporarily
     * t.ls.set('user:123', JSON.stringify({ name: 'Alice', role: 'admin' }));
     * 
     * // Retrieve and parse
     * const userData = JSON.parse(t.ls.get('user:123') || '{}');
     * 
     * // Check all keys
     * const allKeys = t.ls.keys(); // ['user:123', ...]
     * 
     * // Clean up
     * t.ls.remove('user:123');
     * t.ls.clear(); // Remove all data
     * ```
     */
    interface LocalStorage {
        /** Get value. */
        get(key: string): string | null;
        /** Set value. */
        set(key: string, value: string): void;
        /** Remove key. */
        remove(key: string): void;
        /** Clear all storage. */
        clear(): void;
        /** List all keys. */
        keys(): string[];
        /** Stores a complex JavaScript object using V8 serialization and Base64 encoding. */
        setObject(key: string, value: any): void;
        /** Retrieves and deserializes a complex JavaScript object. Returns null if not found or invalid. */
        getObject<T = any>(key: string): T | null;

        /**
         * Serialize a JavaScript value to a V8-compatible binary format.
         * 
         * **Features:**
         * - Supports Map, Set, Date, RegExp, BigInt, TypedArray
         * - Supports Circular references
         * - ~50x faster than JSON.stringify
         * 
         * @param value The value to serialize.
         */
        serialize(value: any): Uint8Array;

        /**
         * Deserialize a V8-compatible binary format back to a JavaScript value.
         * 
         * @param bytes The binary data to deserialize.
         */
        deserialize(bytes: Uint8Array): any;

        /**
         * Register a class for hydration/serialization support.
         */
        register(ClassRef: Function, hydrateFn?: Function, typeName?: string): void;

        /**
         * Hydrate a custom object from data.
         */
        hydrate(typeName: string, data: object): any;

    }

    // ==================== Session ====================

    /**
     * Session API - High-performance session state management
     * 
     * **Implementation:** Native Rust RwLock<HashMap> with composite keys
     * 
     * **Performance:** Same as LocalStorage (~89K-156K ops/sec)
     * 
     * **Characteristics:**
     * - 🔐 Session-scoped storage (isolated per session ID)
     * - ⚡ Sub-millisecond operations
     * - 💾 In-memory only (not persistent)
     * - 🔑 Composite key format: `{sessionId}:{key}`
     * 
     * @example
     * ```typescript
     * // Store shopping cart for session
     * const sessionId = 'sess_abc123';
     * t.session.set(sessionId, 'cart', JSON.stringify([1, 2, 3]));
     * 
     * // Retrieve cart
     * const cart = JSON.parse(t.session.get(sessionId, 'cart') || '[]');
     * 
     * // Clear entire session
     * t.session.clear(sessionId);
     * ```
     */
    interface Session {
        /** Get session value. */
        get(sessionId: string, key: string): string | null;
        /** Set session value. */
        set(sessionId: string, key: string, value: string): void;
        /** Delete session value. */
        delete(sessionId: string, key: string): void;
        /** Clear entire session. */
        clear(sessionId: string): void;
    }

    // ==================== Cookies ====================

    /**
     * Cookie API - HTTP cookie parsing and setting
     */
    interface Cookies {
        /** Parse cookie from request headers. */
        get(req: any, name: string): string | null;
        /** Set Set-Cookie header on response. Options: `{ httpOnly, secure, sameSite, path, maxAge }`. */
        set(res: any, name: string, value: string, options?: CookieOptions): void;
        /** Delete cookie (expire). */
        delete(res: any, name: string): void;
    }

    /**
     * Cookie configuration options
     */
    interface CookieOptions {
        /** Maximum age in seconds */
        maxAge?: number;
        /** Cookie path (default: "/") */
        path?: string;
        /** HTTP-only flag (prevents JavaScript access) */
        httpOnly?: boolean;
        /** Secure flag (HTTPS only) */
        secure?: boolean;
        /** SameSite policy: "Strict", "Lax", or "None" */
        sameSite?: 'Strict' | 'Lax' | 'None';
    }

    // ==================== Response ====================

    /**
     * Response API - Advanced HTTP Response Control
     */
    interface ResponseModule {
        /**
         * Construct a fully custom ResponseObject.
         */
        (options: ResponseOptions): ResponseObject;

        /**
         * Send plain UTF-8 text.
         * Automatically sets `Content-Type: text/plain; charset=utf-8`.
         * @param content Content to send.
         * @param status HTTP status code.
         */
        text(content: string, status?: number): ResponseObject;

        /**
         * Send an HTML document.
         * Automatically sets `Content-Type: text/html; charset=utf-8`.
         * @param content HTML content.
         * @param status HTTP status code.
         */
        html(content: string, status?: number): ResponseObject;

        /**
         * Send JSON-encoded data from a JavaScript object.
         * Automatically sets `Content-Type: application/json`.
         * @param content JSON-serializable object.
         * @param status HTTP status code.
         */
        json(content: any, status?: number): ResponseObject;

        /**
         * Create a Redirect response.
         * @param url Target URL.
         * @param status HTTP status (default: 302).
         */
        redirect(url: string, status?: number): ResponseObject;

        /**
         * Create an empty response.
         * @param status HTTP status (default: 204).
         */
        empty(status?: number): ResponseObject;
    }

    /**
     * Options for customizing the response
     */
    interface ResponseOptions {
        /** HTTP Status Code (e.g., 200, 404, 500) */
        status?: number;
        /** Custom HTTP Headers */
        headers?: Record<string, string>;
        /** Response Body */
        body?: string;
    }

    /**
     * Standardized Response Object consumed by the Titan Rust HTTP server.
     */
    interface ResponseObject {
        type: "response";
        status: number;
        headers: Record<string, string>;
        body: string;
    }
}

export { };
