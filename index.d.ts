// Type definitions for @titanpl/core
// Project: https://github.com/titanpl/core
// Definitions by: TitanPL Team

declare global {
    namespace Titan {
        interface Runtime {
            /**
             * @titanpl/core Extension - Titan Core Standard Library
             * 
             * High-performance runtime APIs for file I/O, cryptography, networking, and data storage.
             */
            "@titanpl/core": TitanCore.Core;

            /**
             * Alias for @titanpl/core
             */
            "titan-core": TitanCore.Core;

            /**
             * File System API - Native file operations
             */
            fs: TitanCore.FileSystem;

            /**
             * Path API - Cross-platform path manipulation
             */
            path: TitanCore.Path;

            /**
             * Cryptography API - Hashing, encryption, random generation
             */
            crypto: TitanCore.Crypto;

            /**
             * Operating System API - System information
             */
            os: TitanCore.OS;

            /**
             * Network API - DNS resolution and IP utilities
             */
            net: TitanCore.Net;

            /**
             * Process API - Runtime process information
             */
            proc: TitanCore.Process;

            /**
             * Time API - Time utilities and delays
             */
            time: TitanCore.Time;

            /**
             * URL API - URL parsing and manipulation
             */
            url: TitanCore.URLModule;

            /**
             * Buffer API - Binary data encoding/decoding
             */
            buffer: TitanCore.BufferModule;

            /**
             * Local Storage API - High-performance in-memory key-value store
             * 
             * **Performance:** ~156,250 reads/sec, ~89,286 writes/sec
             * 
             * - ⚡ RwLock<HashMap> implementation (~0.006ms per read)
             * - 🚀 ~1000x faster than file-based storage
             * - 💾 In-memory only (data lost on restart)
             * - 🔄 Perfect for request-scoped state sharing
             * 
             * @example
             * ```typescript
             * t.ls.set('user:123', 'John Doe');
             * const name = t.ls.get('user:123'); // "John Doe"
             * ```
             */
            ls: TitanCore.LocalStorage;

            /**
             * Alias for `t.ls` - Local Storage
             */
            localStorage: TitanCore.LocalStorage;

            /**
             * Session API - High-performance session state management
             * 
             * **Performance:** ~156,250 reads/sec, ~89,286 writes/sec
             * 
             * - ⚡ RwLock<HashMap> implementation
             * - 🔐 Session-scoped key-value storage
             * - 💨 Sub-millisecond operations
             * 
             * @example
             * ```typescript
             * t.session.set('sess_abc', 'cart', '[1,2,3]');
             * const cart = t.session.get('sess_abc', 'cart');
             * ```
             */
            session: TitanCore.Session;

            /**
             * Cookie API - HTTP cookie parsing and setting
             */
            cookies: TitanCore.Cookies;

            /**
             * Response API - Advanced HTTP Response Management
             * 
             * Enables full control over HTTP responses including:
             * - Custom status codes
             * - Custom headers
             * - Content-Type management
             * - Redirects
             * 
             * @example
             * ```typescript
             * return t.response.text("Hello World");
             * return t.response.json({ ok: true }, { status: 201 });
             * ```
             */
            response: TitanCore.ResponseModule;

            /**
             * Core namespace - Unified access to all APIs
             */
            core: TitanCore.Core;
        }
    }

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
             * Reads file content as UTF-8 string
             * @param path - Absolute or relative file path
             * @returns File content as string
             * @throws Error if file doesn't exist or cannot be read
             */
            readFile(path: string): string;

            /**
             * Writes content to file (creates if doesn't exist)
             * @param path - Target file path
             * @param content - Content to write
             */
            writeFile(path: string, content: string): void;

            /**
             * Reads directory contents
             * @param path - Directory path
             * @returns Array of file/directory names
             */
            readdir(path: string): string[];

            /**
             * Creates directory recursively (like `mkdir -p`)
             * @param path - Directory path to create
             */
            mkdir(path: string): void;

            /**
             * Checks if path exists
             * @param path - Path to check
             * @returns true if exists, false otherwise
             */
            exists(path: string): boolean;

            /**
             * Returns file/directory statistics
             * @param path - Path to stat
             * @returns Stats object with size, type, and modification time
             */
            stat(path: string): Stats;

            /**
             * Removes file or directory (recursive for directories)
             * @param path - Path to remove
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
             * Computes hash of data using specified algorithm
             * @param algorithm - Hash algorithm: "sha256", "sha512", "md5"
             * @param data - Data to hash
             * @returns Hex-encoded hash string
             * @example
             * ```typescript
             * const hash = t.crypto.hash('sha256', 'hello world');
             * ```
             */
            hash(algorithm: 'sha256' | 'sha512' | 'md5', data: string): string;

            /**
             * Generates cryptographically secure random bytes
             * @param size - Number of bytes to generate
             * @returns Hex-encoded random string
             */
            randomBytes(size: number): string;

            /**
             * Generates a UUID v4 string
             * @returns UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000")
             */
            uuid(): string;

            /**
             * Base64 encoding/decoding utilities
             */
            base64: {
                /**
                 * Encodes string to Base64
                 * @param str - String to encode
                 * @returns Base64-encoded string
                 */
                encode(str: string): string;

                /**
                 * Decodes Base64 string
                 * @param str - Base64-encoded string
                 * @returns Decoded string
                 */
                decode(str: string): string;
            };

            /**
             * Encrypts data using AES-256-GCM
             * @param algorithm - Encryption algorithm (e.g., "aes-256-gcm")
             * @param key - Encryption key (32 bytes for AES-256)
             * @param plaintext - Data to encrypt
             * @returns Base64-encoded ciphertext
             */
            encrypt(algorithm: string, key: string, plaintext: string): string;

            /**
             * Decrypts data using AES-256-GCM
             * @param algorithm - Decryption algorithm (e.g., "aes-256-gcm")
             * @param key - Decryption key (must match encryption key)
             * @param ciphertext - Base64-encoded ciphertext
             * @returns Decrypted plaintext
             */
            decrypt(algorithm: string, key: string, ciphertext: string): string;

            /**
             * Computes HMAC (Hash-based Message Authentication Code)
             * @param algorithm - HMAC algorithm: "hmac-sha256", "hmac-sha512"
             * @param key - Secret key
             * @param message - Message to authenticate
             * @returns Hex-encoded HMAC
             */
            hashKeyed(algorithm: 'hmac-sha256' | 'hmac-sha512', key: string, message: string): string;

            /**
             * Constant-time string comparison (prevents timing attacks)
             * @param a - First string
             * @param b - Second string
             * @returns true if strings are equal
             */
            compare(a: string, b: string): boolean;
        }

        // ==================== OS ====================

        /**
         * Operating System API - System information
         */
        interface OS {
            /**
             * Returns the operating system platform
             * @returns Platform name (e.g., "windows", "linux", "darwin")
             */
            platform(): string;

            /**
             * Returns the number of logical CPU cores
             * @returns Number of CPUs
             */
            cpus(): number;

            /**
             * Returns total system memory in bytes
             * @returns Total memory in bytes
             */
            totalMemory(): number;

            /**
             * Returns free system memory in bytes
             * @returns Free memory in bytes
             */
            freeMemory(): number;

            /**
             * Returns the system temporary directory path
             * @returns Temp directory path
             */
            tmpdir(): string;
        }

        // ==================== Network ====================

        /**
         * Network API - DNS resolution and IP utilities
         */
        interface Net {
            /**
             * Resolves hostname to IP addresses
             * @param hostname - Domain name to resolve
             * @returns Array of IP addresses
             */
            resolveDNS(hostname: string): string[];

            /**
             * Returns the local machine's IP address
             * @returns Local IP address
             */
            ip(): string;

            /**
             * Pings a host (currently always returns true)
             * @param host - Host to ping
             * @returns Always true
             */
            ping(host: string): boolean;
        }

        // ==================== Process ====================

        /**
         * Process API - Runtime process information
         */
        interface Process {
            /**
             * Returns the current process ID
             * @returns Process ID (PID)
             */
            pid(): number;

            /**
             * Returns the process uptime in seconds
             * @returns Uptime in seconds
             */
            uptime(): number;

            /**
             * Returns memory usage statistics
             * @returns Memory usage object
             */
            memory(): Record<string, any>;
        }

        // ==================== Time ====================

        /**
         * Time API - Time utilities and delays
         */
        interface Time {
            /**
             * Pauses execution for the specified duration
             * @param ms - Milliseconds to sleep
             * @warning This blocks the V8 isolate - use sparingly!
             */
            sleep(ms: number): void;

            /**
             * Returns the current timestamp in milliseconds
             * @returns Milliseconds since Unix epoch
             */
            now(): number;

            /**
             * Returns the current time as an ISO 8601 string
             * @returns ISO timestamp (e.g., "2024-01-25T10:30:00.000Z")
             */
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
            /**
             * Decodes Base64 string to bytes
             * @param str - Base64-encoded string
             * @returns Uint8Array of decoded bytes
             */
            fromBase64(str: string): Uint8Array;

            /**
             * Encodes bytes or string to Base64
             * @param bytes - Uint8Array or string to encode
             * @returns Base64-encoded string
             */
            toBase64(bytes: Uint8Array | string): string;

            /**
             * Decodes hex string to bytes
             * @param str - Hex-encoded string
             * @returns Uint8Array of decoded bytes
             */
            fromHex(str: string): Uint8Array;

            /**
             * Encodes bytes or string to hex
             * @param bytes - Uint8Array or string to encode
             * @returns Hex-encoded string
             */
            toHex(bytes: Uint8Array | string): string;

            /**
             * Encodes UTF-8 string to bytes
             * @param str - String to encode
             * @returns Uint8Array of UTF-8 bytes
             */
            fromUtf8(str: string): Uint8Array;

            /**
             * Decodes UTF-8 bytes to string
             * @param bytes - Uint8Array of UTF-8 bytes
             * @returns Decoded string
             */
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
            /**
             * Retrieves a value from local storage
             * 
             * **Performance:** ~0.0064ms per operation (~156,250 ops/sec)
             * 
             * @param key - Storage key
             * @returns Stored value or null if not found
             * 
             * @example
             * ```typescript
             * const value = t.ls.get('myKey');
             * if (value !== null) {
             *   console.log('Found:', value);
             * }
             * ```
             */
            get(key: string): string | null;

            /**
             * Stores a value in local storage
             * 
             * **Performance:** ~0.0112ms per operation (~89,286 ops/sec)
             * 
             * @param key - Storage key
             * @param value - Value to store (will be converted to string)
             * 
             * @example
             * ```typescript
             * t.ls.set('counter', '42');
             * t.ls.set('config', JSON.stringify({ theme: 'dark' }));
             * ```
             */
            set(key: string, value: string): void;

            /**
             * Removes a specific key from local storage
             * 
             * @param key - Key to remove
             * 
             * @example
             * ```typescript
             * t.ls.remove('tempData');
             * ```
             */
            remove(key: string): void;

            /**
             * Clears all data from local storage
             * 
             * @warning This removes ALL keys - use with caution!
             * 
             * @example
             * ```typescript
             * t.ls.clear(); // All data removed
             * ```
             */
            clear(): void;

            /**
             * Returns all keys currently in local storage
             * 
             * @returns Array of all storage keys
             * 
             * @example
             * ```typescript
             * const keys = t.ls.keys();
             * console.log('Stored keys:', keys); // ['user:1', 'config', ...]
             * ```
             */
            keys(): string[];
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
            /**
             * Retrieves a value from a session
             * 
             * **Performance:** ~0.0064ms per operation
             * 
             * @param sessionId - Unique session identifier
             * @param key - Key within the session
             * @returns Stored value or null if not found
             */
            get(sessionId: string, key: string): string | null;

            /**
             * Stores a value in a session
             * 
             * **Performance:** ~0.0112ms per operation
             * 
             * @param sessionId - Unique session identifier
             * @param key - Key within the session
             * @param value - Value to store
             */
            set(sessionId: string, key: string, value: string): void;

            /**
             * Deletes a specific key from a session
             * 
             * @param sessionId - Session identifier
             * @param key - Key to delete
             */
            delete(sessionId: string, key: string): void;

            /**
             * Clears all data for a session
             * 
             * @param sessionId - Session identifier to clear
             * 
             * @example
             * ```typescript
             * // Remove all session data when user logs out
             * t.session.clear('sess_abc123');
             * ```
             */
            clear(sessionId: string): void;
        }

        // ==================== Cookies ====================

        /**
         * Cookie API - HTTP cookie parsing and setting
         */
        interface Cookies {
            /**
             * Parses and retrieves a cookie from request headers
             * 
             * @param req - Request object with headers
             * @param name - Cookie name
             * @returns Cookie value (URL-decoded) or null
             * 
             * @example
             * ```typescript
             * const sessionId = t.cookies.get(req, 'session_id');
             * ```
             */
            get(req: any, name: string): string | null;

            /**
             * Sets a cookie in the response headers
             * 
             * @param res - Response object
             * @param name - Cookie name
             * @param value - Cookie value (will be URL-encoded)
             * @param options - Cookie options (maxAge, path, httpOnly, etc.)
             */
            set(res: any, name: string, value: string, options?: CookieOptions): void;

            /**
             * Deletes a cookie by setting maxAge=0
             * 
             * @param res - Response object
             * @param name - Cookie name to delete
             */
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
             * Creates a fully custom response
             * @param options - Response configuration
             */
            (options: ResponseOptions): ResponseObject;

            /**
             * Creates a Plain Text response (Content-Type: text/plain)
             * @param content - Text content
             * @param options - Additional options
             */
            text(content: string, options?: ResponseOptions): ResponseObject;

            /**
             * Creates an HTML response (Content-Type: text/html)
             * @param content - HTML content
             * @param options - Additional options
             */
            html(content: string, options?: ResponseOptions): ResponseObject;

            /**
             * Creates a JSON response (Content-Type: application/json)
             * @param content - JSON serializable object
             * @param options - Additional options
             */
            json(content: any, options?: ResponseOptions): ResponseObject;

            /**
             * Creates a Redirect response (301/302)
             * @param url - URL to redirect to
             * @param status - HTTP Status Code (default: 302)
             */
            redirect(url: string, status?: number): ResponseObject;

            /**
             * Creates an empty response (e.g., 204 No Content)
             * @param status - HTTP Status Code (default: 204)
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
         * Standardized Response Object for the Runtime
         */
        interface ResponseObject {
            _isResponse: true;
            status: number;
            headers: Record<string, string>;
            body: string;
        }
    }
}

export { };
