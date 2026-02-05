/**
 * @titanpl/core
 * The official Core Standard Library for Titan Planet.
 * 
 * This file serves as the single entry point. It handles:
 * 1. Native function lookup
 * 2. JS Wrapper definitions (fs, path, etc.)
 * 3. Global attachment (Side Effects) for t.core and t.*
 * 4. ESM Exports
 */

// 1. Environment & Global Resolution
const _G = (typeof globalThis !== 'undefined' 
    ? globalThis 
    : (typeof self !== 'undefined' 
        ? self 
        : (typeof global !== 'undefined' 
            ? global 
            : {})));

let t;

// Try to find 't' in the scope or global
try {
    if (typeof Titan !== 'undefined') t = Titan;
    else if (_G.t !== undefined) t = _G.t;
    else if (_G.Titan !== undefined) t = _G.Titan;

    // Polyfill global aliases if found
    if (t) {
        if (_G.t === undefined) _G.t = t;
        if (_G.Titan === undefined) _G.Titan = t;
    }
} catch (e) { }

// Fallback for standalone usage (tests, non-runtime)
if (!t) {
    t = {};
    try { _G.t = t; } catch (e) { }
}

const EXT_KEY = "@titanpl/core";

// CRITICAL: Initialize namespaces BEFORE defining getNative and APIs
// This prevents the "cannot read property of undefined" error
if (!t[EXT_KEY]) t[EXT_KEY] = {};
if (!t.native) t.native = {};
if (!t.core) t.core = {};

// 2. Helper Functions
const getNative = (name) => {
    // Primary: Check the extension namespace where natives live
    if (t[EXT_KEY] && typeof t[EXT_KEY][name] === 'function') {
        return t[EXT_KEY][name];
    }

    // Secondary: Legacy global locations
    if (t.native && typeof t.native[name] === 'function') {
        return t.native[name];
    }
    
    if (typeof t[name] === 'function' && !t.__isTitanWrapper && !name.includes(".")) {
        return t[name];
    }

    return null;
};

// Base64 helpers
const _b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const _toB64 = (input) => {
    let output = '';
    let chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    let i = 0;
    const data = (typeof input === 'string') ? input : String.fromCharCode.apply(null, input);
    
    while (i < data.length) {
        chr1 = data.charCodeAt(i++);
        chr2 = data.charCodeAt(i++);
        chr3 = data.charCodeAt(i++);
        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;
        
        if (isNaN(chr2)) enc3 = enc4 = 64;
        else if (isNaN(chr3)) enc4 = 64;
        
        output += _b64chars.charAt(enc1) + _b64chars.charAt(enc2) + 
                  _b64chars.charAt(enc3) + _b64chars.charAt(enc4);
    }
    return output;
};

const _fromB64 = (input) => {
    let output = '';
    let i = 0;
    const data = String(input || "").replace(/[^A-Za-z0-9\+\/\=]/g, "");
    
    while (i < data.length) {
        let enc1 = _b64chars.indexOf(data.charAt(i++));
        let enc2 = _b64chars.indexOf(data.charAt(i++));
        let enc3 = _b64chars.indexOf(data.charAt(i++));
        let enc4 = _b64chars.indexOf(data.charAt(i++));
        
        let chr1 = (enc1 << 2) | (enc2 >> 4);
        let chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        let chr3 = ((enc3 & 3) << 6) | enc4;
        
        output += String.fromCharCode(chr1);
        if (enc3 !== 64) output += String.fromCharCode(chr2);
        if (enc4 !== 64) output += String.fromCharCode(chr3);
    }
    
    const res = new Uint8Array(output.length);
    for (let j = 0; j < output.length; j++) {
        res[j] = output.charCodeAt(j);
    }
    return res;
};

// 3. API Definitions

const fs = {
    readFile: (p) => {
        const f = getNative("fs_read_file");
        if (!f) throw new Error("fs_read_file native not available - Titan runtime required");
        const r = f(p);
        if (typeof r === 'string' && r.startsWith("ERROR:")) throw new Error(r);
        return r;
    },
    writeFile: (p, c) => {
        const f = getNative("fs_write_file");
        if (!f) throw new Error("fs_write_file native not available - Titan runtime required");
        f(p, c);
    },
    readdir: (p) => {
        const f = getNative("fs_readdir");
        if (!f) return [];
        try { 
            return JSON.parse(f(p)); 
        } catch (e) { 
            return []; 
        }
    },
    mkdir: (p) => {
        const f = getNative("fs_mkdir");
        if (!f) throw new Error("fs_mkdir native not available - Titan runtime required");
        f(p);
    },
    exists: (p) => {
        const f = getNative("fs_exists");
        return f ? f(p) : false;
    },
    stat: (p) => {
        const f = getNative("fs_stat");
        if (!f) return {};
        try { 
            return JSON.parse(f(p)); 
        } catch (e) { 
            return {}; 
        }
    },
    remove: (p) => {
        const f = getNative("fs_remove");
        if (!f) throw new Error("fs_remove native not available - Titan runtime required");
        f(p);
    }
};

const path = {
    join: (...a) => {
        return a
            .filter(Boolean)
            .map(x => String(x).replace(/\\/g, '/'))
            .join('/')
            .replace(/\/+/g, '/');
    },
    resolve: (...a) => {
        let r = path.join(...a);
        const f = getNative("path_cwd");
        return (!r.startsWith('/') && !/^[a-zA-Z]:/.test(r) && f) 
            ? path.join(f(), r) 
            : r;
    },
    dirname: (p) => {
        const parts = String(p).split('/');
        return parts.slice(0, -1).join('/') || '.';
    },
    basename: (p) => {
        return String(p).split('/').pop() || '';
    },
    extname: (p) => {
        const str = String(p);
        let i = str.lastIndexOf('.');
        return i > 0 ? str.slice(i) : '';
    }
};

const crypto = {
    hash: (a, d) => {
        const f = getNative("crypto_hash");
        return f ? f(a, d) : "";
    },
    randomBytes: (s) => {
        const f = getNative("crypto_random_bytes");
        return f ? f(s) : "";
    },
    uuid: () => {
        const f = getNative("crypto_uuid");
        return f ? f() : "";
    },
    encrypt: (a, k, p) => {
        const f = getNative("crypto_encrypt");
        if (!f) throw new Error("crypto_encrypt native not available - Titan runtime required");
        const r = f(a, JSON.stringify({ key: k, plaintext: p }));
        if (typeof r === 'string' && r.startsWith("ERROR:")) {
            throw new Error(r.slice(6));
        }
        return r;
    },
    decrypt: (a, k, c) => {
        const f = getNative("crypto_decrypt");
        if (!f) throw new Error("crypto_decrypt native not available - Titan runtime required");
        const r = f(a, JSON.stringify({ key: k, ciphertext: c }));
        if (typeof r === 'string' && r.startsWith("ERROR:")) {
            throw new Error(r.slice(6));
        }
        return r;
    },
    compare: (a, b) => a === b,
    hashKeyed: (a, k, m) => {
        const f = getNative("crypto_hash_keyed");
        return f ? f(a, JSON.stringify({ key: k, message: m })) : "";
    }
};

const ls = {
    get: (k) => {
        const f = getNative("ls_get");
        return f ? f(k) : null;
    },
    set: (k, v) => {
        const f = getNative("ls_set");
        if (f) f(k, String(v));
    },
    remove: (k) => {
        const f = getNative("ls_remove");
        if (f) f(k);
    },
    clear: () => {
        const f = getNative("ls_clear");
        if (f) f();
    },
    keys: () => {
        const f = getNative("ls_keys");
        if (!f) return [];
        try { 
            return JSON.parse(f()); 
        } catch (e) { 
            return []; 
        }
    },
    serialize: (v) => {
        const f = getNative("serialize");
        return f ? f(v) : null;
    },
    deserialize: (b) => {
        const f = getNative("deserialize");
        return f ? f(b) : null;
    },
    setObject: (k, v) => {
        const s = ls.serialize(v);
        if (s) ls.set(k, _toB64(s));
    },
    getObject: (k) => {
        const b = ls.get(k);
        if (!b) return null;
        try { 
            return ls.deserialize(_fromB64(b)); 
        } catch (e) { 
            return null; 
        }
    }
};

const buffer = {
    fromBase64: _fromB64,
    toBase64: _toB64
};

const os = {
    info: () => {
        const f = getNative("os_info");
        if (!f) return {};
        try { 
            return JSON.parse(f()); 
        } catch (e) { 
            return {}; 
        }
    },
    platform: () => os.info().platform || "unknown",
    cpus: () => os.info().cpus || 1,
    totalMemory: () => os.info().totalMemory || 0,
    freeMemory: () => os.info().freeMemory || 0,
    tmpdir: () => os.info().tmpdir || "/tmp"
};

const net = {
    resolveDNS: (h) => {
        const f = getNative("net_resolve");
        if (!f) return [];
        try { 
            return JSON.parse(f(h)); 
        } catch (e) { 
            return []; 
        }
    },
    ip: () => {
        const f = getNative("net_ip");
        return f ? f() : "127.0.0.1";
    }
};

const proc = {
    info: () => {
        const f = getNative("proc_info");
        if (!f) return {};
        try { 
            return JSON.parse(f()); 
        } catch (e) { 
            return {}; 
        }
    },
    pid: () => proc.info().pid || 0,
    run: (c, a, d) => {
        const f = getNative("proc_run");
        if (!f) return {};
        try { 
            return JSON.parse(f(JSON.stringify({ cmd: c, args: a || [], cwd: d || "" }))); 
        } catch (e) { 
            return {}; 
        }
    },
    kill: (p) => {
        const f = getNative("proc_kill");
        return f ? f(Number(p)) : false;
    },
    list: () => {
        const f = getNative("proc_list");
        if (!f) return [];
        try { 
            return JSON.parse(f()); 
        } catch (e) { 
            return []; 
        }
    }
};

const time = {
    sleep: (ms) => {
        const f = getNative("time_sleep");
        if (f) f(Number(ms));
    },
    now: () => Date.now()
};

const session = {
    get: (s, k) => {
        const f = getNative("session_get");
        return f ? f(s, k) : null;
    },
    set: (s, k, v) => {
        const f = getNative("session_set");
        if (f) f(s, JSON.stringify({ key: k, value: v }));
    },
    delete: (s, k) => {
        const f = getNative("session_delete");
        if (f) f(s, k);
    },
    clear: (s) => {
        const f = getNative("session_clear");
        if (f) f(s);
    }
};

const cookies = {
    get: (req, name) => {
        if (!req || !req.headers || !req.headers.cookie) return null;
        const match = req.headers.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
        return match ? match[2] : null;
    },
    set: (res, name, value, options = {}) => {
        if (!res) return;
        res.headers = res.headers || {};
        
        let cookie = `${name}=${value}`;
        if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
        if (options.path) cookie += `; Path=${options.path}`;
        if (options.httpOnly) cookie += `; HttpOnly`;
        if (options.secure) cookie += `; Secure`;
        if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
        
        if (res.headers['Set-Cookie']) {
            if (Array.isArray(res.headers['Set-Cookie'])) {
                res.headers['Set-Cookie'].push(cookie);
            } else {
                res.headers['Set-Cookie'] = [res.headers['Set-Cookie'], cookie];
            }
        } else {
            res.headers['Set-Cookie'] = cookie;
        }
    }
};

const url = {
    parse: (s) => {
        try {
            return new URL(s);
        } catch (e) {
            return null;
        }
    },
    SearchParams: (typeof URLSearchParams !== 'undefined' 
        ? URLSearchParams 
        : class {
            constructor(i) { this.q = i || ""; }
            toString() { return String(this.q); }
        })
};

const response = (o) => ({
    _isResponse: true,
    status: o.status || 200,
    headers: o.headers || {},
    body: o.body || ""
});

response.json = (c, o = {}) => response({
    ...o,
    headers: { "Content-Type": "application/json", ...(o.headers || {}) },
    body: JSON.stringify(c)
});

response.text = (c, o = {}) => response({
    ...o,
    body: String(c)
});

response.html = (c, o = {}) => response({
    ...o,
    headers: { "Content-Type": "text/html", ...(o.headers || {}) },
    body: String(c)
});

response.redirect = (u, s = 302) => response({
    status: s,
    headers: { "Location": u }
});

// Main API object
const API = {
    fs,
    path,
    crypto,
    ls,
    buffer,
    os,
    net,
    proc,
    time,
    session,
    cookies,
    url,
    response,
    __isTitanWrapper: true
};

// 4. Global Attachment (Side Effects)
try {
    if (t.log && typeof t.log === 'function') {
        t.log(EXT_KEY, "Extension loading...");
    }

    // A. Inherit into t[@titanpl/core]
    Object.keys(API).forEach(key => {
        if (t[EXT_KEY][key] === API[key]) return;

        try {
            Reflect.defineProperty(t[EXT_KEY], key, {
                value: API[key],
                writable: true,
                enumerable: true,
                configurable: true
            });
        } catch (e) {
            try { 
                t[EXT_KEY][key] = API[key]; 
            } catch (e2) { /* Silent */ }
        }
    });

    // Prototype Injection (Fallback)
    try {
        if (Object.getPrototypeOf(t[EXT_KEY]) !== API) {
            Object.setPrototypeOf(t[EXT_KEY], API);
        }
    } catch (e) { /* Silent */ }

    // B. Attach to t.core
    Object.assign(t.core, API);

    // C. Attach to Direct Global t.*
    Object.keys(API).forEach(key => {
        if (key.startsWith("__")) return;

        try {
            // Merging behavior: If t[key] exists and is an object, merge. Else overwrite.
            if (t[key] && typeof t[key] === 'object' && typeof API[key] === 'object') {
                Object.assign(t[key], API[key]);
            } else if (!(key in t) || t[key] === undefined) {
                // Only assign if it doesn't exist or is undefined
                t[key] = API[key];
            }
        } catch (e) {
            try {
                Object.defineProperty(t, key, {
                    value: API[key],
                    writable: true,
                    configurable: true,
                    enumerable: true
                });
            } catch (e2) { /* Silent */ }
        }
    });

    if (t.log && typeof t.log === 'function') {
        t.log(EXT_KEY, "Extension loaded successfully");
    }
} catch (e) {
    // Silent in restrictive environments
    // but allow ESM exports to work
}

// 5. ESM Exports
export { fs, path, crypto, ls, buffer, os, net, proc, time, session, cookies, url, response };
export const core = API;

// Export the runtime for direct access if needed
export { t as runtime };

// Default export
export default API;