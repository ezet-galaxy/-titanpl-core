# @titanpl/core

The official Core Standard Library for **Titan Planet** - a high-performance JavaScript runtime.

## Installation

```bash
npm install @titanpl/core
```

## Overview

`@titanpl/core` provides essential standard library modules for Titan applications:

| Module | Description |
|--------|-------------|
| `fs` | File system operations (read, write, mkdir, exists, stat, remove) |
| `path` | Path manipulation utilities (join, resolve, extname, dirname, basename) |
| `crypto` | Cryptographic functions (hash, randomBytes, uuid, base64) |
| `os` | Operating system information (platform, cpus, memory) |
| `net` | Network utilities (DNS resolve, IP address) |
| `proc` | Process information (pid, uptime) |
| `time` | Time utilities (sleep, now, timestamp) |
| `url` | URL parsing and manipulation |

## Usage

Once installed, the extension automatically attaches to the Titan runtime:

```javascript
// Access via t.core
const content = t.core.fs.readFile("config.json");
const joined = t.core.path.join("foo", "bar", "baz.txt");
const uuid = t.core.crypto.uuid();

// Or via individual modules on t
const exists = t.fs.exists("./data");
const now = t.time.now();
```

## API Reference

### fs (File System)

```javascript
t.fs.readFile(path)          // Read file contents as string
t.fs.writeFile(path, content) // Write string to file
t.fs.readdir(path)           // List directory contents
t.fs.mkdir(path)             // Create directory
t.fs.exists(path)            // Check if path exists
t.fs.stat(path)              // Get file/directory stats
t.fs.remove(path)            // Remove file or directory
```

### path

```javascript
t.path.join(...parts)        // Join path segments
t.path.resolve(...parts)     // Resolve to absolute path
t.path.extname(path)         // Get file extension
t.path.dirname(path)         // Get directory name
t.path.basename(path)        // Get file name
```

### crypto

```javascript
t.crypto.hash(algo, data)    // Hash data (sha256, sha512, etc.)
t.crypto.randomBytes(size)   // Generate random bytes
t.crypto.uuid()              // Generate UUID v4
t.crypto.base64.encode(str)  // Base64 encode
t.crypto.base64.decode(str)  // Base64 decode
t.crypto.compare(a, b)       // Constant-time string comparison
```

### os

```javascript
t.os.platform()              // Get OS platform
t.os.cpus()                  // Get CPU count
t.os.totalMemory()           // Get total memory
t.os.freeMemory()            // Get free memory
t.os.tmpdir()                // Get temp directory path
```

### net

```javascript
t.net.resolveDNS(hostname)   // Resolve DNS
t.net.ip()                   // Get local IP address
```

### proc

```javascript
t.proc.pid()                 // Get process ID
t.proc.uptime()              // Get process uptime
```

### time

```javascript
t.time.sleep(ms)             // Sleep for milliseconds
t.time.now()                 // Get current timestamp (ms)
t.time.timestamp()           // Get ISO timestamp string
```

### url

```javascript
t.url.parse(urlString)       // Parse URL string
t.url.format(urlObject)      // Format URL object to string
new t.url.SearchParams(query) // Parse query string
```

## Native Bindings

This extension includes native Rust bindings for high-performance file system and OS operations. The native library is automatically loaded when available.

## Requirements

- Titan SDK >= 0.1.7
- Node.js >= 18.0.0 (for development)

## License

ISC © ezetgalaxy
