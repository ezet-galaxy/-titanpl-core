/**
 * Titan Core Extension - Bootstrap & Polyfill
 * 
 * This script runs automatically on extension load.
 * It strictly adheres to the Titan Extension Pattern to ensuring robust, production-ready initialization.
 */

(function () {
    // 1. Environment & Global Polyfill
    const _G = (typeof globalThis !== 'undefined' ? globalThis : (typeof self !== 'undefined' ? self : {}));
    if (typeof _G.t === 'undefined') {
        if (typeof _G.Titan !== 'undefined') _G.t = _G.Titan;
        else _G.t = {}; // Minimal stub if running completely standalone
    }
    if (typeof _G.Titan === 'undefined') _G.Titan = _G.t;

    const t = _G.t;
    const EXT_KEY = "@titanpl/core";

    // 2. Lifecycle Log
    if (t.log) t.log(EXT_KEY, "Extension loading...");

    // 3. Native Helpers
    // The Runtime injects native bindings directly into t[EXT_KEY] before this script runs.
    // We must enable a lookup that finds them there.
    const getNative = (name) => {
        // Primary: Check the extension namespace where natives live
        if (t[EXT_KEY] && typeof t[EXT_KEY][name] === 'function') return t[EXT_KEY][name];

        // Secondary: Legacy global locations
        if (t.native && typeof t.native[name] === 'function') return t.native[name];
        if (typeof t[name] === 'function' && !t.__isTitanWrapper && !name.includes(".")) return t[name];

        return null;
    };

    // 4. Utility Functions (Base64)
    const _b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const _toB64 = (input) => { /* ... condensed base64 ... */ let output = ''; let chr1, chr2, chr3, enc1, enc2, enc3, enc4; let i = 0; const data = (typeof input === 'string') ? input : String.fromCharCode.apply(null, input); while (i < data.length) { chr1 = data.charCodeAt(i++); chr2 = data.charCodeAt(i++); chr3 = data.charCodeAt(i++); enc1 = chr1 >> 2; enc2 = ((chr1 & 3) << 4) | (chr2 >> 4); enc3 = ((chr2 & 15) << 2) | (chr3 >> 6); enc4 = chr3 & 63; if (isNaN(chr2)) enc3 = enc4 = 64; else if (isNaN(chr3)) enc4 = 64; output += _b64chars.charAt(enc1) + _b64chars.charAt(enc2) + _b64chars.charAt(enc3) + _b64chars.charAt(enc4); } return output; };
    const _fromB64 = (input) => { /* ... condensed base64 ... */ let output = ''; let i = 0; const data = String(input || "").replace(/[^A-Za-z0-9\+\/\=]/g, ""); while (i < data.length) { let enc1 = _b64chars.indexOf(data.charAt(i++)); let enc2 = _b64chars.indexOf(data.charAt(i++)); let enc3 = _b64chars.indexOf(data.charAt(i++)); let enc4 = _b64chars.indexOf(data.charAt(i++)); let chr1 = (enc1 << 2) | (enc2 >> 4); let chr2 = ((enc2 & 15) << 4) | (enc3 >> 2); let chr3 = ((enc3 & 3) << 6) | enc4; output += String.fromCharCode(chr1); if (enc3 != 64) output += String.fromCharCode(chr2); if (enc4 != 64) output += String.fromCharCode(chr3); } const res = new Uint8Array(output.length); for (let j = 0; j < output.length; j++) res[j] = output.charCodeAt(j); return res; };

    // 5. API Definition
    // We define the pure JS wrappers here. They call into getNative().

    const fs = {
        readFile: (p) => { const f = getNative("fs_read_file"); if (!f) throw new Error("fs_read_file missing"); const r = f(p); if (typeof r === 'string' && r.startsWith("ERROR:")) throw new Error(r); return r; },
        writeFile: (p, c) => { const f = getNative("fs_write_file"); f && f(p, c); },
        readdir: (p) => { const f = getNative("fs_readdir"); try { return JSON.parse(f ? f(p) : "[]"); } catch (e) { return []; } },
        mkdir: (p) => { const f = getNative("fs_mkdir"); f && f(p); },
        exists: (p) => { const f = getNative("fs_exists"); return f ? f(p) : false; },
        stat: (p) => { const f = getNative("fs_stat"); try { return JSON.parse(f ? f(p) : "{}"); } catch (e) { return {}; } },
        remove: (p) => { const f = getNative("fs_remove"); f && f(p); }
    };

    const path = {
        join: (...a) => a.filter(Boolean).map(x => String(x).replace(/\\/g, '/')).join('/').replace(/\/+/g, '/'),
        resolve: (...a) => { let r = path.join(...a); const f = getNative("path_cwd"); return (!r.startsWith('/') && !/^[a-zA-Z]:/.test(r) && f) ? path.join(f(), r) : r; },
        dirname: (p) => p.split('/').slice(0, -1).join('/') || '.',
        basename: (p) => p.split('/').pop() || '',
        extname: (p) => { let i = p.lastIndexOf('.'); return i > 0 ? p.slice(i) : ''; }
    };

    const crypto = {
        hash: (a, d) => { const f = getNative("crypto_hash"); return f ? f(a, d) : ""; },
        randomBytes: (s) => { const f = getNative("crypto_random_bytes"); return f ? f(s) : ""; },
        uuid: () => { const f = getNative("crypto_uuid"); return f ? f() : ""; },
        encrypt: (a, k, p) => { const f = getNative("crypto_encrypt"); const r = f ? f(a, JSON.stringify({ key: k, plaintext: p })) : null; return (typeof r === 'string' && r.startsWith("ERROR:")) ? (() => { throw new Error(r.slice(6)); })() : r; },
        decrypt: (a, k, c) => { const f = getNative("crypto_decrypt"); const r = f ? f(a, JSON.stringify({ key: k, ciphertext: c })) : null; return (typeof r === 'string' && r.startsWith("ERROR:")) ? (() => { throw new Error(r.slice(6)); })() : r; },
        compare: (a, b) => a === b,
        hashKeyed: (a, k, m) => { const f = getNative("crypto_hash_keyed"); return f ? f(a, JSON.stringify({ key: k, message: m })) : ""; }
    };

    const ls = {
        get: (k) => { const f = getNative("ls_get"); return f ? f(k) : null; },
        set: (k, v) => { const f = getNative("ls_set"); f && f(k, String(v)); },
        remove: (k) => { const f = getNative("ls_remove"); f && f(k); },
        clear: () => { const f = getNative("ls_clear"); f && f(); },
        keys: () => { const f = getNative("ls_keys"); try { return JSON.parse(f ? f() : "[]"); } catch (e) { return []; } },
        serialize: (v) => { const f = getNative("serialize"); return f ? f(v) : null; },
        deserialize: (b) => { const f = getNative("deserialize"); return f ? f(b) : null; },
        setObject: (k, v) => { const s = ls.serialize(v); if (s) ls.set(k, _toB64(s)); },
        getObject: (k) => { const b = ls.get(k); if (!b) return null; try { return ls.deserialize(_fromB64(b)); } catch (e) { return null; } }
    };

    const buffer = { fromBase64: _fromB64, toBase64: _toB64 };

    const os = {
        info: () => { const f = getNative("os_info"); try { return JSON.parse(f ? f() : "{}"); } catch (e) { return {}; } },
        platform: () => os.info().platform || "unknown",
        cpus: () => os.info().cpus || 1,
        totalMemory: () => os.info().totalMemory || 0,
        freeMemory: () => os.info().freeMemory || 0,
        tmpdir: () => os.info().tmpdir || "/tmp"
    };

    const net = {
        resolveDNS: (h) => { const f = getNative("net_resolve"); try { return JSON.parse(f ? f(h) : "[]"); } catch (e) { return []; } },
        ip: () => { const f = getNative("net_ip"); return f ? f() : "127.0.0.1"; }
    };

    const proc = {
        info: () => { const f = getNative("proc_info"); try { return JSON.parse(f ? f() : "{}"); } catch (e) { return {}; } },
        pid: () => proc.info().pid || 0,
        run: (c, a, d) => { const f = getNative("proc_run"); try { return JSON.parse(f ? f(JSON.stringify({ cmd: c, args: a || [], cwd: d || "" })) : "{}"); } catch (e) { return {}; } },
        kill: (p) => { const f = getNative("proc_kill"); return f ? f(Number(p)) : false; },
        list: () => { const f = getNative("proc_list"); try { return JSON.parse(f ? f() : "[]"); } catch (e) { return []; } }
    };

    const time = {
        sleep: (ms) => { const f = getNative("time_sleep"); f && f(Number(ms)); },
        now: () => Date.now()
    };

    const session = {
        get: (s, k) => { const f = getNative("session_get"); return f ? f(s, k) : null; },
        set: (s, k, v) => { const f = getNative("session_set"); f && f(s, JSON.stringify({ key: k, value: v })); },
        delete: (s, k) => { const f = getNative("session_delete"); f && f(s, k); },
        clear: (s) => { const f = getNative("session_clear"); f && f(s); }
    };

    const cookies = {
        get: (req, name) => {
            if (!req.headers || !req.headers.cookie) return null;
            const match = req.headers.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
            return match ? match[2] : null;
        },
        set: (res, name, value, options = {}) => {
            res.headers = res.headers || {};
            let cookie = `${name}=${value}`;
            if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
            if (options.path) cookie += `; Path=${options.path}`;
            if (options.httpOnly) cookie += `; HttpOnly`;
            if (options.secure) cookie += `; Secure`;
            if (res.headers['Set-Cookie']) {
                if (Array.isArray(res.headers['Set-Cookie'])) res.headers['Set-Cookie'].push(cookie);
                else res.headers['Set-Cookie'] = [res.headers['Set-Cookie'], cookie];
            } else { res.headers['Set-Cookie'] = cookie; }
        }
    };

    const url = { parse: (s) => new URL(s), SearchParams: URLSearchParams };

    const response = (o) => ({ _isResponse: true, status: o.status || 200, headers: o.headers || {}, body: o.body || "" });
    response.json = (c, o = {}) => response({ ...o, headers: { "Content-Type": "application/json", ...(o.headers || {}) }, body: JSON.stringify(c) });
    response.text = (c, o = {}) => response({ ...o, body: String(c) });
    response.html = (c, o = {}) => response({ ...o, headers: { "Content-Type": "text/html", ...(o.headers || {}) }, body: String(c) });
    response.redirect = (u, s = 302) => response({ status: s, headers: { "Location": u } });

    // 6. Assembly
    // Merge all APIs into a single object
    const API = {
        fs, path, crypto, ls, buffer, os, net, proc, time, session, cookies, url, response,
        __isTitanWrapper: true
    };

    // 7. Global Attachment (The "Perfect" Injection)

    // A. Inject into the Extension Namespace (Preserving existing Natives!)
    // This effectively "upgrades" the native object with high-level JS wrappers.
    t[EXT_KEY] = Object.assign(t[EXT_KEY] || {}, API);

    // B. Inject into t.core (Standard Library container)
    // We create t.core if it doesn't exist, and merge our API into it.
    if (!t.core) t.core = {};
    Object.assign(t.core, API);

    // C. Inject into Direct Global t.* (Shortcuts)
    // We iterate the API and attach modules (fs, ls, etc.) directly to t.
    // We strictly use Object.assign to merge if the key exists (like t.ls), ensuring we don't clobber.
    // If it's a primitive or missing, we set it.
    Object.keys(API).forEach(key => {
        if (key.startsWith("__")) return; // Skip internal flags

        const val = API[key];

        // If it's already there (maybe from another init or native injection), we MERGE options.
        if (t[key] && typeof t[key] === 'object' && typeof val === 'object') {
            Object.assign(t[key], val);
        } else {
            // Otherwise, we define it.
            // Use defineProperty to ensure it's writable/configurable if possible
            try { t[key] = val; }
            catch (e) {
                try { Object.defineProperty(t, key, { value: val, writable: true, configurable: true, enumerable: true }); } catch (i) { }
            }
        }
    });

    // 8. Final Log
    if (t.log) t.log(EXT_KEY, "Extension loaded!");

})();
