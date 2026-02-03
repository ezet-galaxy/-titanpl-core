declare var fs_read_file: any;
declare var fs_write_file: any;
declare var fs_readdir: any;
declare var fs_mkdir: any;
declare var fs_exists: any;
declare var fs_stat: any;
declare var fs_remove: any;
declare var path_cwd: any;
declare var crypto_hash: any;
declare var crypto_random_bytes: any;
declare var crypto_uuid: any;
declare var os_info: any;
declare var net_resolve: any;
declare var net_ip: any;
declare var proc_info: any;
declare var proc_run: any;
declare var proc_kill: any;
declare var proc_list: any;
declare var time_sleep: any;

// Type definitions for @titanpl/core - Global Augmentations
// Project: https://github.com/titanpl/core
// Definitions by: TitanPL Team
//
// This file is a SCRIPT (no top-level import/export).
// TypeScript auto-applies these declarations globally when the package is installed
// and referenced via tsconfig "types" or triple-slash directive.

// ==================== Titan Core Namespace ====================

declare namespace TitanCore {
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
         * @returns Statistics object.
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
         * Base64 encoding/decoding utilities.
         */
        base64: {
            /** Encode string to Base64 */
            encode(str: string): string;
            /** Decode Base64 to string */
            decode(str: string): string;
        };

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
     * Process API - Runtime process information and execution
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
         * @param cwd Current working directory.
         * @returns Object containing the PID of the spawned process.
         */
        run(command: string, args: string[], cwd?: string): { ok: boolean, pid: number, cwd: string };
        /**
         * Kill a process by PID.
         * @param pid Process ID to kill.
         */
        kill(pid: number): boolean;
        /**
         * List running processes.
         */
        list(): Record<string, any>[];
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
        get(key: string): string | null;
        set(key: string, value: string): void;
        has(key: string): boolean;
        delete(key: string): void;
        toString(): string;
        entries(): [string, string][];
        keys(): string[];
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
     * @example
     * ```typescript
     * t.ls.set('user:123', JSON.stringify({ name: 'Alice', role: 'admin' }));
     * const userData = JSON.parse(t.ls.get('user:123') || '{}');
     * t.ls.clear();
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
         */
        serialize(value: any): Uint8Array;

        /**
         * Deserialize a V8-compatible binary format back to a JavaScript value.
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
     * @example
     * ```typescript
     * const sessionId = 'sess_abc123';
     * t.session.set(sessionId, 'cart', JSON.stringify([1, 2, 3]));
     * const cart = JSON.parse(t.session.get(sessionId, 'cart') || '[]');
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
        /** Set Set-Cookie header on response. */
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
        /** SameSite policy */
        sameSite?: 'Strict' | 'Lax' | 'None';
    }

    // ==================== Response ====================

    /**
     * Response API - Advanced HTTP Response Control
     */
    interface ResponseModule {
        /** Construct a fully custom ResponseObject. */
        (options: ResponseOptions): ResponseObject;
        /** Send plain UTF-8 text. */
        text(content: string, options?: ResponseOptions): ResponseObject;
        /** Send an HTML document. */
        html(content: string, options?: ResponseOptions): ResponseObject;
        /** Send JSON-encoded data. */
        json(content: any, options?: ResponseOptions): ResponseObject;
        /** Create a Redirect response. */
        redirect(url: string, status?: number): ResponseObject;
        /** Create an empty response. */
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
        _isResponse: true;
        status: number;
        headers: Record<string, string>;
        body: string;
    }
}

// ==================== Titan Runtime Global ====================

declare namespace Titan {
    interface Runtime {
        /**
         * # @titanpl/core
         * The official Core Standard Library for Titan Planet.
         *
         * ```javascript
         * const { fs, crypto, os } = t.core;
         * ```
         */
        "@titanpl/core": TitanCore.Core;

        /** Alias for @titanpl/core */
        "titan-core": TitanCore.Core;

        /** File System - Native file operations backed by Rust. */
        fs: TitanCore.FileSystem;

        /** Path manipulation utilities. */
        path: TitanCore.Path;

        /** Cryptographic utilities using native Rust implementations. */
        crypto: TitanCore.Crypto;

        /** Operating System - Deep system introspection. */
        os: TitanCore.OS;

        /** Network - Low-level networking and DNS utilities. */
        net: TitanCore.Net;

        /** Process - Runtime execution control and monitoring. */
        proc: TitanCore.Process;

        /** Time - High-resolution timing and scheduling. */
        time: TitanCore.Time;

        /** URL - Robust URL parsing and construction. */
        url: TitanCore.URLModule;

        /** Buffer - High-performance binary data handling. */
        buffer: TitanCore.BufferModule;

        /** Local Storage - High-performance in-memory key-value store. */
        ls: TitanCore.LocalStorage;

        /** Alias for `t.ls` - Local Storage */
        localStorage: TitanCore.LocalStorage;

        /** Session - High-performance session management. */
        session: TitanCore.Session;

        /** Cookie - Standard-compliant HTTP cookie management. */
        cookies: TitanCore.Cookies;

        /** Response - HTTP Response Builder. */
        response: TitanCore.ResponseModule;

        /** Core namespace - Unified access to all APIs. */
        core: TitanCore.Core;
    }
}