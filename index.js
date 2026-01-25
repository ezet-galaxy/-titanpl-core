const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function local_btoa(input) {
    let str = String(input);
    let output = '';

    for (let i = 0; i < str.length; i += 3) {
        const char1 = str.charCodeAt(i);
        const char2 = str.charCodeAt(i + 1);
        const char3 = str.charCodeAt(i + 2);

        const enc1 = char1 >> 2;
        const enc2 = ((char1 & 3) << 4) | (char2 >> 4);
        let enc3 = ((char2 & 15) << 2) | (char3 >> 6);
        let enc4 = char3 & 63;

        if (isNaN(char2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(char3)) {
            enc4 = 64;
        }

        output += b64chars.charAt(enc1) + b64chars.charAt(enc2);
        output += (enc3 === 64) ? '=' : b64chars.charAt(enc3);
        output += (enc4 === 64) ? '=' : b64chars.charAt(enc4);
    }

    return output;
}

function local_atob(input) {
    // Remove whitespace and padding '='
    let str = String(input).replace(/[\t\n\f\r =]/g, "");
    let output = '';

    for (let i = 0; i < str.length; i += 4) {
        const c1Str = str.charAt(i);
        const c2Str = str.charAt(i + 1);
        const c3Str = str.charAt(i + 2);
        const c4Str = str.charAt(i + 3);

        const e1 = b64chars.indexOf(c1Str);
        const e2 = c2Str ? b64chars.indexOf(c2Str) : -1;
        const e3 = c3Str ? b64chars.indexOf(c3Str) : -1;
        const e4 = c4Str ? b64chars.indexOf(c4Str) : -1;

        // e1 and e2 are required
        if (e1 < 0 || e2 < 0) continue;

        // Shift and mask to reconstruct bytes
        const c1 = (e1 << 2) | (e2 >> 4);
        output += String.fromCharCode(c1);

        if (e3 !== -1) {
            const c2 = ((e2 & 15) << 4) | (e3 >> 2);
            output += String.fromCharCode(c2);
        }
        if (e4 !== -1) {
            const c3 = ((e3 & 3) << 6) | e4;
            output += String.fromCharCode(c3);
        }
    }

    return output;
}

function local_utf8_encode(str) {
    let result = [];
    for (let i = 0; i < str.length; i++) {
        let c = str.charCodeAt(i);
        if (c < 0x80) { result.push(c); }
        else if (c < 0x800) {
            result.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
        }
        else if (c < 0xd800 || c >= 0xe000) {
            result.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
        }
        else {
            i++;
            c = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
            result.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
        }
    }
    return new Uint8Array(result);
}

function local_utf8_decode(bytes) {
    let str = "";
    let i = 0;
    while (i < bytes.length) {
        let c = bytes[i++];
        if (c > 127) {
            if (c > 191 && c < 224) {
                c = ((c & 31) << 6) | (bytes[i++] & 63);
            } else if (c > 223 && c < 240) {
                c = ((c & 15) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63);
            } else if (c > 239 && c < 248) {
                c = ((c & 7) << 18) | ((bytes[i++] & 63) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63);
            }
        }
        if (c <= 0xffff) str += String.fromCharCode(c);
        else if (c <= 0x10ffff) {
            c -= 0x10000;
            str += String.fromCharCode(c >> 10 | 0xd800) + String.fromCharCode(c & 0x3ff | 0xdc00);
        }
    }
    return str;
}


// Native bindings are loaded by the runtime into t["@titanpl/core"]
const natives = t["@titanpl/core"] || {};


// Native Function bindings
const native_fs_read_file = natives.fs_read_file;
const native_fs_write_file = natives.fs_write_file;
const native_fs_readdir = natives.fs_readdir;
const native_fs_mkdir = natives.fs_mkdir;
const native_fs_exists = natives.fs_exists;
const native_fs_stat = natives.fs_stat;
const native_fs_remove = natives.fs_remove;
const native_path_cwd = natives.path_cwd;

const native_crypto_hash = natives.crypto_hash;
const native_crypto_random_bytes = natives.crypto_random_bytes;
const native_crypto_uuid = natives.crypto_uuid;
const native_crypto_encrypt = natives.crypto_encrypt;
const native_crypto_decrypt = natives.crypto_decrypt;
const native_crypto_hash_keyed = natives.crypto_hash_keyed;
const native_crypto_compare = natives.crypto_compare;

const native_os_info = natives.os_info;
const native_net_resolve = natives.net_resolve;
const native_net_ip = natives.net_ip;
const native_proc_info = natives.proc_info;
const native_time_sleep = natives.time_sleep;

const native_ls_get = natives.ls_get;
const native_ls_set = natives.ls_set;
const native_ls_remove = natives.ls_remove;
const native_ls_clear = natives.ls_clear;
const native_ls_keys = natives.ls_keys;



const native_session_get = natives.session_get;
const native_session_set = natives.session_set;
const native_session_delete = natives.session_delete;
const native_session_clear = natives.session_clear;

// --- FS ---
/** File System module */
const fs = {
    /** Reads file content as UTF-8 string */
    readFile: (path) => {
        if (!native_fs_read_file) throw new Error("Native fs_read_file not found");
        const res = native_fs_read_file(path);
        if (res && res.startsWith("ERROR:")) throw new Error(res);
        return res;
    },
    /** Writes content to file */
    writeFile: (path, content) => {
        if (!native_fs_write_file) throw new Error("Native fs_write_file not found");
        native_fs_write_file(path, content);
    },
    /** Reads directory contents */
    readdir: (path) => {
        if (!native_fs_readdir) throw new Error("Native fs_readdir not found");
        const res = native_fs_readdir(path);
        try {
            return JSON.parse(res);
        } catch (e) {
            return [];
        }
    },
    /** Creates direction recursively */
    mkdir: (path) => {
        if (!native_fs_mkdir) throw new Error("Native fs_mkdir not found");
        native_fs_mkdir(path);
    },
    /** Checks if path exists */
    exists: (path) => {
        if (!native_fs_exists) throw new Error("Native fs_exists not found");
        return native_fs_exists(path);
    },
    /** Returns file stats */
    stat: (path) => {
        if (!native_fs_stat) throw new Error("Native fs_stat not found");
        const res = native_fs_stat(path);
        try {
            return JSON.parse(res);
        } catch (e) {
            return {};
        }
    },
    /** Removes file or directory */
    remove: (path) => {
        if (!native_fs_remove) throw new Error("Native fs_remove not found");
        native_fs_remove(path);
    }
};

// --- Path ---
/** Path manipulation module */
const path = {
    join: (...args) => {
        return args
            .map((part, i) => {
                if (!part) return '';
                let p = part.replace(/\\/g, '/');
                if (i === 0) return p.trim().replace(/[\/]*$/g, '');
                return p.trim().replace(/(^[\/]*|[\/]*$)/g, '');
            })
            .filter(x => x.length)
            .join('/');
    },
    resolve: (...args) => {
        let resolved = '';
        for (let arg of args) {
            resolved = path.join(resolved, arg);
        }
        if (!resolved.startsWith('/')) {
            const isWindowsAbs = /^[a-zA-Z]:\\/.test(resolved) || resolved.startsWith('\\');
            if (!isWindowsAbs && native_path_cwd) {
                const cwd = native_path_cwd();
                if (cwd) {
                    resolved = path.join(cwd, resolved);
                }
            }
        }
        return resolved;
    },
    extname: (p) => {
        const parts = p.split('.');
        return parts.length > 1 && !p.startsWith('.') ? '.' + parts.pop() : '';
    },
    dirname: (p) => {
        const parts = p.split('/');
        parts.pop();
        return parts.join('/') || '.';
    },
    basename: (p) => p.split('/').pop()
};

// --- Crypto ---
/** Cryptography module */
const crypto = {
    hash: (algo, data) => native_crypto_hash ? native_crypto_hash(algo, data) : "",
    randomBytes: (size) => native_crypto_random_bytes ? native_crypto_random_bytes(size) : "",
    uuid: () => native_crypto_uuid ? native_crypto_uuid() : "",
    base64: {
        encode: (str) => local_btoa(str),
        decode: (str) => local_atob(str),
    },
    // Extended API
    /** Encrypts data using AES-256-GCM. Returns Base64 string. */
    encrypt: (algorithm, key, plaintext) => {
        if (!native_crypto_encrypt) throw new Error("Native crypto_encrypt not found");
        const res = native_crypto_encrypt(algorithm, JSON.stringify({ key, plaintext }));
        if (res.startsWith("ERROR:")) throw new Error(res.substring(6));
        return res;
    },
    /** Decrypts data using AES-256-GCM. Returns plaintext string. */
    decrypt: (algorithm, key, ciphertext) => {
        if (!native_crypto_decrypt) throw new Error("Native crypto_decrypt not found");
        const res = native_crypto_decrypt(algorithm, JSON.stringify({ key, ciphertext }));
        if (res.startsWith("ERROR:")) throw new Error(res.substring(6));
        return res;
    },
    /** Computes HMAC-SHA256/512. Returns Hex string. */
    hashKeyed: (algorithm, key, message) => {
        if (!native_crypto_hash_keyed) throw new Error("Native crypto_hash_keyed not found");
        const res = native_crypto_hash_keyed(algorithm, JSON.stringify({ key, message }));
        if (res.startsWith("ERROR:")) throw new Error(res.substring(6));
        return res;
    },
    /** Constant-time string comparison */
    compare: (a, b) => {
        if (native_crypto_compare) return native_crypto_compare(a, b);
        // Fallback insecure
        if (a.length !== b.length) return false;
        let mismatch = 0;
        for (let i = 0; i < a.length; ++i) {
            mismatch |= (a.charCodeAt(i) ^ b.charCodeAt(i));
        }
        return mismatch === 0;
    }
};

// --- Buffer ---
// Helper for hex
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Buffer utility module */
const buffer = {
    /** Creates Uint8Array from Base64 string */
    fromBase64: (str) => {
        const binary = local_atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },
    /** encoded Uint8Array or String to Base64 string */
    toBase64: (bytes) => {
        let binary = '';
        if (typeof bytes === 'string') {
            return local_btoa(bytes);
        }
        // Uint8Array
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return local_btoa(binary);
    },
    /** Creates Uint8Array from Hex string */
    fromHex: (str) => hexToBytes(str),
    /** Encodes bytes to Hex string */
    toHex: (bytes) => {
        if (typeof bytes === 'string') {
            return bytesToHex(local_utf8_encode(bytes));
        }
        return bytesToHex(bytes);
    },
    /** Creates Uint8Array from UTF-8 string */
    fromUtf8: (str) => local_utf8_encode(str),
    /** Decodes bytes to UTF-8 string */
    toUtf8: (bytes) => local_utf8_decode(bytes)
};

// --- Local Storage ---
/** High-performance in-memory Local Storage (backed by native RwLock<HashMap>) */
const ls = {
    get: (key) => {
        if (!native_ls_get) throw new Error("Native ls_get not found");
        return native_ls_get(key);
    },
    set: (key, value) => {
        if (!native_ls_set) throw new Error("Native ls_set not found");
        native_ls_set(key, String(value));
    },
    remove: (key) => {
        if (!native_ls_remove) throw new Error("Native ls_remove not found");
        native_ls_remove(key);
    },
    clear: () => {
        if (!native_ls_clear) throw new Error("Native ls_clear not found");
        native_ls_clear();
    },
    keys: () => {
        if (!native_ls_keys) throw new Error("Native ls_keys not found");
        const result = native_ls_keys();
        try {
            return JSON.parse(result);
        } catch (e) {
            return [];
        }
    }
};

// --- Sessions ---
/** High-performance in-memory Session Management (backed by native RwLock<HashMap>) */
const session = {
    get: (sessionId, key) => {
        if (!native_session_get) throw new Error("Native session_get not found");
        return native_session_get(sessionId, key);
    },
    set: (sessionId, key, value) => {
        if (!native_session_set) throw new Error("Native session_set not found");
        native_session_set(sessionId, key, String(value));
    },
    delete: (sessionId, key) => {
        if (!native_session_delete) throw new Error("Native session_delete not found");
        native_session_delete(sessionId, key);
    },
    clear: (sessionId) => {
        if (!native_session_clear) throw new Error("Native session_clear not found");
        native_session_clear(sessionId);
    }
};


// --- Cookies ---
/** HTTP Cookie Utilities */
const cookies = {
    /** Parses cookie from request headers */
    get: (req, name) => {
        if (!req || !req.headers) return null;
        const cookieHeader = req.headers.cookie;
        if (!cookieHeader) return null;
        const cookies = cookieHeader.split(';');
        for (let c of cookies) {
            const [k, v] = c.trim().split('=');
            if (k === name) return decodeURIComponent(v);
        }
        return null;
    },
    /** Sets Set-Cookie header on response */
    set: (res, name, value, options = {}) => {
        if (!res || !res.setHeader) return;
        let cookie = `${name}=${encodeURIComponent(value)}`;
        if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
        if (options.path) cookie += `; Path=${options.path}`;
        if (options.httpOnly) cookie += `; HttpOnly`;
        if (options.secure) cookie += `; Secure`;
        if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;

        let prev = res.getHeader ? res.getHeader('Set-Cookie') : null;
        if (prev) {
            if (Array.isArray(prev)) {
                prev.push(cookie);
                res.setHeader('Set-Cookie', prev);
            } else {
                res.setHeader('Set-Cookie', [prev, cookie]);
            }
        } else {
            res.setHeader('Set-Cookie', cookie);
        }
    },
    /** Deletes cookie by setting maxAge=0 */
    delete: (res, name) => {
        cookies.set(res, name, "", { maxAge: 0, path: '/' });
    }
};



// --- Response ---
/** Advanced HTTP Response Management */
const response = (options) => {
    return {
        _isResponse: true,
        status: options.status || 200,
        headers: options.headers || {},
        body: options.body || ""
    };
};

response.text = (content, options = {}) => {
    return {
        _isResponse: true,
        status: options.status || 200,
        headers: { "Content-Type": "text/plain", ...(options.headers || {}) },
        body: content
    };
};

response.html = (content, options = {}) => {
    return {
        _isResponse: true,
        status: options.status || 200,
        headers: { "Content-Type": "text/html; charset=utf-8", ...(options.headers || {}) },
        body: content
    };
};

response.json = (content, options = {}) => {
    return {
        _isResponse: true,
        status: options.status || 200,
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        body: JSON.stringify(content)
    };
};

response.redirect = (url, status = 302) => {
    return {
        _isResponse: true,
        status: status,
        headers: { "Location": url },
        body: ""
    };
};

response.empty = (status = 204) => {
    return {
        _isResponse: true,
        status: status,
        headers: {},
        body: ""
    };
};

// --- OS ---
const os = {
    platform: () => {
        if (!native_os_info) return "unknown";
        const info = JSON.parse(native_os_info());
        return info.platform;
    },
    cpus: () => {
        if (!native_os_info) return 1;
        const info = JSON.parse(native_os_info());
        return info.cpus;
    },
    totalMemory: () => {
        if (!native_os_info) return 0;
        const info = JSON.parse(native_os_info());
        return info.totalMemory;
    },
    freeMemory: () => {
        if (!native_os_info) return 0;
        const info = JSON.parse(native_os_info());
        return info.freeMemory;
    },
    tmpdir: () => {
        if (!native_os_info) return '/tmp';
        try {
            const info = JSON.parse(native_os_info());
            return info.tempDir || '/tmp';
        } catch (e) {
            return '/tmp';
        }
    }
};

// --- Net ---
const net = {
    resolveDNS: (hostname) => {
        if (!native_net_resolve) return [];
        return JSON.parse(native_net_resolve(hostname));
    },
    ip: () => native_net_ip ? native_net_ip() : "127.0.0.1",
    ping: (host) => true
};

// --- Proc ---
const proc = {
    pid: () => {
        if (!native_proc_info) return 0;
        const info = JSON.parse(native_proc_info());
        return info.pid;
    },
    uptime: () => {
        if (!native_proc_info) return 0;
        const info = JSON.parse(native_proc_info());
        return info.uptime;
    },
    memory: () => ({})
};

// --- Time ---
const time = {
    sleep: (ms) => {
        if (native_time_sleep) native_time_sleep(ms);
    },
    now: () => Date.now(),
    timestamp: () => new Date().toISOString()
};

// --- URL ---
class TitanURLSearchParams {
    constructor(init = '') {
        this._params = {};
        if (typeof init === 'string') {
            const query = init.startsWith('?') ? init.slice(1) : init;
            query.split('&').forEach(pair => {
                const [key, value] = pair.split('=').map(decodeURIComponent);
                if (key) this._params[key] = value || '';
            });
        } else if (typeof init === 'object') {
            Object.assign(this._params, init);
        }
    }
    get(key) { return this._params[key] || null; }
    set(key, value) { this._params[key] = String(value); }
    has(key) { return key in this._params; }
    delete(key) { delete this._params[key]; }
    toString() {
        return Object.entries(this._params)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&');
    }
    entries() { return Object.entries(this._params); }
    keys() { return Object.keys(this._params); }
    values() { return Object.values(this._params); }
}

const url = {
    parse: (str) => {
        if (typeof URL !== 'undefined') {
            return new URL(str);
        }
        const match = str.match(/^(https?:)\/\/([^/:]+)(?::(\d+))?(\/[^?#]*)?(\?[^#]*)?(#.*)?$/);
        if (!match) throw new Error('Invalid URL');
        return {
            protocol: match[1],
            hostname: match[2],
            port: match[3] || '',
            pathname: match[4] || '/',
            search: match[5] || '',
            hash: match[6] || ''
        };
    },
    format: (obj) => obj.toString ? obj.toString() : String(obj),
    SearchParams: TitanURLSearchParams
};

// Create the main core export object (following titan-valid pattern)
const core = {
    fs,
    path,
    crypto,
    os,
    net,
    proc,
    time,
    url,
    buffer, // t.core.buffer
    ls,
    session,
    cookies,
    response
};

t.fs = fs;
t.path = path;
t.crypto = crypto;
t.os = os;
t.net = net;
t.proc = proc;
t.time = time;
t.url = url;

// New Global Modules
t.buffer = buffer;
t.ls = ls;
t.localStorage = ls;
t.session = session;
t.cookies = cookies;
t.response = response;

// Attach core as unified namespace (main access point)
t.core = core;

// Register as extension under multiple names for compatibility
t["titan-core"] = core;
t["@titanpl/core"] = core;

// Also register in t.exts
if (!t.exts) t.exts = {};
t.exts["titan-core"] = core;
t.exts["@titanpl/core"] = core;