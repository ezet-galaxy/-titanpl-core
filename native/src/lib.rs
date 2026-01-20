mod crypto_impl;
mod storage_impl;

use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;
use serde_json::json;
use sha2::{Sha256, Sha512, Digest};
use uuid::Uuid;
use md5::Md5;
use rand::Rng;

// --- FS ---

#[no_mangle]
pub extern "C" fn fs_read_file(path: String) -> String {
    println!("[Native] fs_read_file called with: '{}'", path);
    match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) => {
            println!("[Native] fs_read_file error: {}", e);
            format!("ERROR: {}", e)
        },
    }
}

#[no_mangle]
pub extern "C" fn fs_write_file(path: String, content: String) {
    let _ = fs::write(path, content);
}

#[no_mangle]
pub extern "C" fn fs_readdir(path: String) -> String {
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(path) {
        for entry in read_dir {
            if let Ok(entry) = entry {
                if let Ok(name) = entry.file_name().into_string() {
                    entries.push(name);
                }
            }
        }
    }
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

#[no_mangle]
pub extern "C" fn fs_mkdir(path: String) {
    let _ = fs::create_dir_all(path);
}

#[no_mangle]
pub extern "C" fn fs_exists(path: String) -> bool {
    Path::new(&path).exists()
}

#[no_mangle]
pub extern "C" fn fs_stat(path: String) -> String {
    if let Ok(meta) = fs::metadata(&path) {
        let file_type = if meta.is_dir() { "directory" } else { "file" };
        let size = meta.len();
        let json = json!({
            "type": file_type,
            "size": size
        });
        json.to_string()
    } else {
        "{}".to_string()
    }
}

#[no_mangle]
pub extern "C" fn fs_remove(path: String) {
    if let Ok(meta) = fs::metadata(&path) {
        if meta.is_dir() {
            let _ = fs::remove_dir_all(path);
        } else {
            let _ = fs::remove_file(path);
        }
    }
}

#[no_mangle]
pub extern "C" fn path_cwd() -> String {
    if let Ok(cwd) = std::env::current_dir() {
        cwd.to_string_lossy().into_owned()
    } else {
        "".to_string()
    }
}

// --- Crypto ---

#[no_mangle]
pub extern "C" fn crypto_hash(algo: String, data: String) -> String {
    match algo.as_str() {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        },
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        },
        "md5" => {
            let mut hasher = Md5::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        },
        _ => "".to_string()
    }
}

#[no_mangle]
pub extern "C" fn crypto_random_bytes(size: f64) -> String {
    let size = size as usize;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; size];
    rng.fill(&mut bytes[..]);
    hex::encode(bytes)
}

#[no_mangle]
pub extern "C" fn crypto_uuid() -> String {
    Uuid::new_v4().to_string()
}

// New Crypto Extensions
#[no_mangle]
pub extern "C" fn crypto_encrypt(algo: String, json_str: String) -> String {
    let inputs: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return "ERROR:Invalid JSON arguments".to_string()
    };
    let key = inputs["key"].as_str().unwrap_or("");
    let plaintext = inputs["plaintext"].as_str().unwrap_or("");
    
    match crypto_impl::encrypt(&algo, key, plaintext) {
        Ok(result) => result,
        Err(e) => format!("ERROR:{}", e) 
    }
}

#[no_mangle]
pub extern "C" fn crypto_decrypt(algo: String, json_str: String) -> String {
    let inputs: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return "ERROR:Invalid JSON arguments".to_string()
    };
    let key = inputs["key"].as_str().unwrap_or("");
    let ciphertext = inputs["ciphertext"].as_str().unwrap_or("");

    match crypto_impl::decrypt(&algo, key, ciphertext) {
        Ok(result) => result,
        Err(e) => format!("ERROR:{}", e)
    }
}

#[no_mangle]
pub extern "C" fn crypto_hash_keyed(algo: String, json_str: String) -> String {
     let inputs: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return "ERROR:Invalid JSON arguments".to_string()
    };
    let key = inputs["key"].as_str().unwrap_or("");
    let message = inputs["message"].as_str().unwrap_or("");

    match crypto_impl::hash_keyed(&algo, key, message) {
        Ok(result) => result,
        Err(e) => format!("ERROR:{}", e)
    }
}

#[no_mangle]
pub extern "C" fn crypto_compare(a: String, b: String) -> bool {
    crypto_impl::compare(&a, &b)
}


// --- OS ---

#[no_mangle]
pub extern "C" fn os_info() -> String {
    let info = sys_info::os_type().unwrap_or("unknown".to_string());
    let release = sys_info::os_release().unwrap_or("unknown".to_string());
    let cpus = sys_info::cpu_num().unwrap_or(1);
    let mem = sys_info::mem_info().unwrap_or(sys_info::MemInfo { total: 0, free: 0, avail: 0, buffers: 0, cached: 0, swap_total: 0, swap_free: 0 });
    
    let json = json!({
        "platform": info,
        "release": release,
        "cpus": cpus,
        "totalMemory": mem.total,
        "freeMemory": mem.free
    });
    json.to_string()
}

// --- Net ---

#[no_mangle]
pub extern "C" fn net_resolve(hostname: String) -> String {
    match dns_lookup::lookup_host(&hostname) {
        Ok(ips) => {
            let ips_str: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
            serde_json::to_string(&ips_str).unwrap_or("[]".to_string())
        },
        Err(_) => "[]".to_string()
    }
}

#[no_mangle]
pub extern "C" fn net_ip() -> String {
    if let Ok(my_local_ip) = local_ip_address::local_ip() {
        my_local_ip.to_string()
    } else {
        "127.0.0.1".to_string()
    }
}

// --- Proc ---

#[no_mangle]
pub extern "C" fn proc_info() -> String {
    let pid = std::process::id();
    #[cfg(windows)]
    let uptime = 0;
    #[cfg(not(windows))]
    let uptime = sys_info::boottime().map(|t| t.tv_sec).unwrap_or(0);

    let json = json!({
        "pid": pid,
        "uptime": uptime
    });
    json.to_string()
}

// --- Time ---

#[no_mangle]
pub extern "C" fn time_sleep(ms: f64) {
    println!("[Native] Sleeping for {} ms", ms);
    thread::sleep(Duration::from_millis(ms as u64));
    println!("[Native] Woke up");
}

// --- Local Storage ---

#[no_mangle]
pub extern "C" fn ls_get(key: String) -> String {
    storage_impl::ls_get(&key).unwrap_or("".to_string())
}

#[no_mangle]
pub extern "C" fn ls_set(key: String, value: String) {
    let _ = storage_impl::ls_set(&key, &value);
}

#[no_mangle]
pub extern "C" fn ls_remove(key: String) {
    let _ = storage_impl::ls_remove(&key);
}

#[no_mangle]
pub extern "C" fn ls_clear() {
    let _ = storage_impl::ls_clear();
}

#[no_mangle]
pub extern "C" fn ls_keys() -> String {
    match storage_impl::ls_keys() {
        Ok(keys) => serde_json::to_string(&keys).unwrap_or("[]".to_string()),
        Err(_) => "[]".to_string()
    }
}

// --- Sessions ---

#[no_mangle]
pub extern "C" fn session_get(id: String, key: String) -> String {
     storage_impl::session_get(&id, &key).unwrap_or("".to_string())
}

#[no_mangle]
pub extern "C" fn session_set(id: String, json_str: String) {
    let inputs: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return
    };
    let key = inputs["key"].as_str().unwrap_or("");
    let value = inputs["value"].as_str().unwrap_or("");
    let _ = storage_impl::session_set(&id, key, value);
}

#[no_mangle]
pub extern "C" fn session_delete(id: String, key: String) {
    let _ = storage_impl::session_delete(&id, &key);
}

#[no_mangle]
pub extern "C" fn session_clear(id: String) {
    let _ = storage_impl::session_clear(&id);
}
