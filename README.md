# @titanpl/core
The official Core Standard Library for Titan Planet - a high-performance JavaScript runtime extension.

## Overview
`@titanpl/core` provides essential standard library modules for Titan applications, bridging high-performance Rust native implementations with an easy-to-use JavaScript API.

## Installation
```bash
npm install @titanpl/core
```

## Usage
The extension automatically attaches to the Titan runtime. You can access it via `t.core` or the `t` global object alias.

```javascript
// Access via t.core (Recommended)
const { fs, crypto, os } = t.core;

// Read a file
const content = fs.readFile("config.json");

// Generate UUID
const id = crypto.uuid();
```

## API Reference

### `fs` (File System)
Perform synchronous file system operations.
- `fs.readFile(path: string): string` - Read file content as UTF-8 string.
- `fs.writeFile(path: string, content: string): void` - Write string content to file.
- `fs.exists(path: string): boolean` - Check if path exists.
- `fs.mkdir(path: string): void` - Create a directory (recursive).
- `fs.remove(path: string): void` - Remove file or directory.
- `fs.readdir(path: string): string[]` - List directory contents.
- `fs.stat(path: string): object` - Get file statistics (`{ type: "file"|"directory", size: number }`).

### `path` (Path Manipulation)
Utilities for handling file paths.
- `path.join(...parts: string[]): string` - Join path segments.
- `path.resolve(...parts: string[]): string` - Resolve path to absolute.
- `path.dirname(path: string): string` - Get directory name.
- `path.basename(path: string): string` - Get base file name.
- `path.extname(path: string): string` - Get file extension.

### `crypto` (Cryptography)
Cryptographic utilities using native Rust implementations.
- `crypto.hash(algo: string, data: string): string` - Hash data. Supported algos: `sha256`, `sha512`, `md5`.
- `crypto.randomBytes(size: number): string` - Generate random bytes as hex string.
- `crypto.uuid(): string` - Generate a UUID v4.
- `crypto.compare(hash: string, target: string): boolean` - Constant-time comparison.
- `crypto.encrypt(algorithm: string, key: string, plaintext: string): string` - AES-256-GCM Encrypt (Returns Base64).
- `crypto.decrypt(algorithm: string, key: string, ciphertext: string): string` - AES-256-GCM Decrypt.
- `crypto.hashKeyed(algo: string, key: string, message: string): string` - HMAC-SHA256/512.

**Example:**
```javascript
const hash = t.core.crypto.hash("sha256", "hii");
const valid = t.core.crypto.compare(
    "a1a3b09875f9e9acade5623e1cca680009a6c9e0452489931cfa5b0041f4d290", 
    hash
);
```

### `buffer` (Buffer Utilities)
Utilities for binary data manipulation.
- `buffer.fromBase64(str: string): Uint8Array` - Decode Base64 string.
- `buffer.toBase64(bytes: Uint8Array|string): string` - Encode to Base64.
- `buffer.fromHex(str: string): Uint8Array` - Decode Hex string.
- `buffer.toHex(bytes: Uint8Array|string): string` - Encode to Hex.
- `buffer.fromUtf8(str: string): Uint8Array` - Encode UTF-8 string to bytes.
- `buffer.toUtf8(bytes: Uint8Array): string` - Decode bytes to UTF-8 string.

### `ls` / `localStorage` (Persistent Storage)
Key-value storage persisted to disk (via Sled).
- `ls.get(key: string): string|null` - Get value.
- `ls.set(key: string, value: string): void` - Set value.
- `ls.remove(key: string): void` - Remove key.
- `ls.clear(): void` - Clear all storage.
- `ls.keys(): string[]` - List all keys.
- `ls.serialize(value: any): Uint8Array` - Serialize any JS value to V8 format (using native v8::ValueSerializer). Supports Maps, Sets, Dates, Uint8Arrays, and cyclical references.
- `ls.deserialize(bytes: Uint8Array): any` - Deserialize V8-format bytes back to JS value.
- `ls.register(ClassRef, hydrateFn?, typeName?): void` - Register a class for hydration support.
- `ls.hydrate(typeName, data): any` - Hydrate a custom object from data.
- `ls.setObject(key: string, value: any): void` - Stores a complex JavaScript object using V8 serialization.
- `ls.getObject(key: string): any` - Retrieves and deserializes a complex JavaScript object.

**Serialization Example:**
```javascript
const data = { 
    date: new Date(),
    map: new Map([['key', 'value']]),
    buffer: new Uint8Array([1, 2, 3])
};

// Serialize complex objects to Uint8Array
const bytes = t.ls.serialize(data);

// Restore original object structure
const restored = t.ls.deserialize(bytes);
t.log(restored.map.get('key')); // 'value'
t.log(restored.buffer instanceof Uint8Array); // true
```

### `session` (Server-side Sessions)
Session management backed by persistent storage.
- `session.get(sessionId: string, key: string): string|null` - Get session value.
- `session.set(sessionId: string, key: string, value: string): void` - Set session value.
- `session.delete(sessionId: string, key: string): void` - Delete session value.
- `session.clear(sessionId: string): void` - Clear entire session.

### `cookies` (HTTP Cookies)
Cookie parsing and serialization.
- `cookies.get(req: object, name: string): string|null` - Parse cookie from request headers.
- `cookies.set(res: object, name: string, value: string, options: object): void` - Set `Set-Cookie` header on response. Options: `{ httpOnly, secure, sameSite, path, maxAge }`.
- `cookies.delete(res: object, name: string): void` - Delete cookie (expire).

### `os` (Operating System)
Get system information.
- `os.platform(): string` - OS platform (e.g., `linux`, `windows`).
- `os.cpus(): number` - Number of CPU cores.
- `os.totalMemory(): number` - Total system memory in bytes.
- `os.freeMemory(): number` - Free system memory in bytes.
- `os.tmpdir(): string` - Temporary directory path.

### `net` (Network)
Network utilities.
- `net.resolveDNS(hostname: string): string[]` - Resolve hostname to IP addresses.
- `net.ip(): string` - Get local IP address.

### `proc` (Process)

The `t.proc` module provides capabilities for interacting with the operating system processes, including retrieving system information, spawning new processes, and managing running tasks.

#### `proc.run(command, args, cwd)`

Spawns a new background process.

- **command** `string`: The executable name or path to run.
- **args** `string[]` (optional): An array of string arguments to pass to the executable. Default: `[]`.
- **cwd** `string` (optional): The working directory for the process. 
  - If absolute (e.g., `C:/App`), it is used as-is.
  - If relative (e.g., `./data`), it is resolved relative to the Titan host process current directory.
  - If omitted or empty, defaults to the current working directory.

**Returns:**
An object containing the process start status:
```javascript
{
  "ok": true,       // "true" if the spawn call succeeded
  "pid": 12345,     // The Process ID of the started process
  "cwd": "C:\\..."  // The actual resolved working directory used
}
```

**Example:**
```javascript
// Run a simple command
t.proc.run("notepad.exe");

// Run with arguments
t.proc.run("git", ["status"]);

// Run in a specific directory
t.proc.run("npm", ["install"], "./my-project");
```

#### `proc.list()`

Retrieves a list of currently running processes on the system.

**Returns:**
An array of process objects, where each object typically contains:
- `pid` `number`: Process ID.
- `name` `string`: Name of the executable (e.g., `node.exe`).
- `cpu` `number`: CPU usage (platform dependent).
- `memory` `number`: Memory usage in bytes.
- `cmd` `string[]`: Command line arguments (if accessible).

**Example:**
```javascript
const processes = t.proc.list();
const nodeProcs = processes.filter(p => p.name === "node.exe");
t.log(`Found ${nodeProcs.length} Node processes.`);
```

#### `proc.kill(pid)`

Attempts to terminate a process by its Process ID (PID).

- **pid** `number`: The ID of the process to kill.

**Returns:**
- `true` if the signal was sent successfully.
- `false` if the operation failed (e.g., process not found or permission denied).

**Example:**
```javascript
t.proc.kill(12345);
```

#### `proc.pid()`

Returns the Process ID (PID) of the current Titan runtime instance.

**Returns:** `number`

**Example:**
```javascript
t.log("Current PID:", t.proc.pid());
```

#### `proc.uptime()`

Returns the system uptime in seconds.

**Returns:** `number`

**Example:**
```javascript
const days = t.proc.uptime() / 86400;
t.log(`System has been up for ${days.toFixed(1)} days.`);
```

#### `proc.memory()`

*Currently returns an empty object `{}`. Placeholder for future implementation of memory usage stats.*

### `time` (Time)
Time utilities.
- `time.sleep(ms: number): void` - Sleep for specified milliseconds.
- `time.now(): number` - Current timestamp (ms).
- `time.timestamp(): string` - Current ISO timestamp.

### `url` (URL)
URL parsing and manipulation.
- `url.parse(urlString: string): URLObject` - Parse URL string.
- `url.format(urlObject: object): string` - Format URL object.
- `new url.SearchParams(query: string|object)` - Handle query strings.

### **`response` (HTTP Response Builder)**

Utilities for constructing HTTP responses.
All response methods return a standardized ResponseObject consumed by the Titan Rust HTTP server.

- `response.text(content: string, status?: number): ResponseObject` – Send plain text.
- `response.html(content: string, status?: number): ResponseObject` – Send HTML content.
- `response.json(data: any, status?: number): ResponseObject` – Send JSON-encoded data.

### **`response.text(content: string, status?: number)`**

Send plain UTF-8 text.

```js
return t.response.text("Hello World");
```

Automatically sets:

* `Content-Type: text/plain; charset=utf-8`

### **`response.html(content: string, status?: number)`**

Send an HTML document.

```js
return t.response.html("<h1>Hello</h1>");
```

Automatically sets:

* `Content-Type: text/html; charset=utf-8`

### **`response.json(data: any, status?: number)`**

Send JSON from a JavaScript object.

```js
return t.response.json({ ok: true });
```

Automatically sets:

* `Content-Type: application/json`

JSON serialization:

* Objects, arrays, primitives, and nested structures are supported.

### **ResponseObject**

Standard structure returned by all response methods:

```ts
{
  type: "response",
  status: number,
  headers: { [key: string]: string },
  body: string
}
```

### **Examples**

```js
// Text
t.response.text("pong");

// HTML
t.response.html("<h1>Welcome</h1>");

// JSON
t.response.json({ version: "1.0.0" });
```


## Native Bindings
This extension includes native Rust bindings for high-performance operations. The native library is automatically loaded by the Titan Runtime.

