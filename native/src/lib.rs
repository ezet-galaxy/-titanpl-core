use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;
use serde_json::json;
use sha2::{Sha256, Sha512, Digest};
use md5::Md5;
use rand::Rng;
use uuid::Uuid;


// Helper to convert C string to Rust string
fn ptr_to_string(ptr: *const c_char) -> String {
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

// Helper to convert Rust string to C string pointer
fn string_to_ptr(s: String) -> *const c_char {
    CString::new(s).unwrap().into_raw()
}

// --- FS ---

#[unsafe(no_mangle)]
pub extern "C" fn fs_read_file(path: *const c_char) -> *const c_char {
    let path_str = ptr_to_string(path);
    match fs::read_to_string(&path_str) {
        Ok(content) => string_to_ptr(content),
        Err(_) => string_to_ptr("".to_string()), // TODO: Better error handling?
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_write_file(path: *const c_char, content: *const c_char) {
    let path_str = ptr_to_string(path);
    let content_str = ptr_to_string(content);
    let _ = fs::write(path_str, content_str);
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_readdir(path: *const c_char) -> *const c_char {
    let path_str = ptr_to_string(path);
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(path_str) {
        for entry in read_dir {
            if let Ok(entry) = entry {
                if let Ok(name) = entry.file_name().into_string() {
                    entries.push(name);
                }
            }
        }
    }
    string_to_ptr(serde_json::to_string(&entries).unwrap())
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_mkdir(path: *const c_char) {
    let path_str = ptr_to_string(path);
    let _ = fs::create_dir_all(path_str);
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_exists(path: *const c_char) -> bool {
    let path_str = ptr_to_string(path);
    Path::new(&path_str).exists()
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_stat(path: *const c_char) -> *const c_char {
    let path_str = ptr_to_string(path);
    if let Ok(meta) = fs::metadata(&path_str) {
        let file_type = if meta.is_dir() { "directory" } else { "file" };
        let size = meta.len();
        let json = json!({
            "type": file_type,
            "size": size
        });
        string_to_ptr(json.to_string())
    } else {
        string_to_ptr("{}".to_string())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fs_remove(path: *const c_char) {
    let path_str = ptr_to_string(path);
    if let Ok(meta) = fs::metadata(&path_str) {
        if meta.is_dir() {
            let _ = fs::remove_dir_all(path_str);
        } else {
            let _ = fs::remove_file(path_str);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn path_cwd() -> *const c_char {
    if let Ok(cwd) = std::env::current_dir() {
        string_to_ptr(cwd.to_string_lossy().into_owned())
    } else {
        string_to_ptr("".to_string())
    }
}

// --- Crypto ---

#[unsafe(no_mangle)]
pub extern "C" fn crypto_hash(algo: *const c_char, data: *const c_char) -> *const c_char {
    let algo_str = ptr_to_string(algo);
    let data_str = ptr_to_string(data);
    let res = match algo_str.as_str() {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(data_str);
            format!("{:x}", hasher.finalize())
        },
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(data_str);
            format!("{:x}", hasher.finalize())
        },
        "md5" => {
            let mut hasher = Md5::new();
            hasher.update(data_str);
            format!("{:x}", hasher.finalize())
        },
        _ => "".to_string()
    };
    string_to_ptr(res)
}

#[unsafe(no_mangle)]
pub extern "C" fn crypto_random_bytes(size: f64) -> *const c_char {
    let size = size as usize;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; size];
    rng.fill(&mut bytes[..]);
    // Return hex string of bytes
    string_to_ptr(hex::encode(bytes))
}

#[unsafe(no_mangle)]
pub extern "C" fn crypto_uuid() -> *const c_char {
    string_to_ptr(Uuid::new_v4().to_string())
}

// --- OS ---

#[unsafe(no_mangle)]
pub extern "C" fn os_info() -> *const c_char {
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
    string_to_ptr(json.to_string())
}

// --- Net ---

#[unsafe(no_mangle)]
pub extern "C" fn net_resolve(hostname: *const c_char) -> *const c_char {
    let hostname_str = ptr_to_string(hostname);
    match dns_lookup::lookup_host(&hostname_str) {
        Ok(ips) => {
            let ips_str: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
            string_to_ptr(serde_json::to_string(&ips_str).unwrap())
        },
        Err(_) => string_to_ptr("[]".to_string())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn net_ip() -> *const c_char {
    if let Ok(my_local_ip) = local_ip_address::local_ip() {
        string_to_ptr(my_local_ip.to_string())
    } else {
        string_to_ptr("127.0.0.1".to_string())
    }
}

// --- Proc ---

#[unsafe(no_mangle)]
pub extern "C" fn proc_info() -> *const c_char {
    let pid = std::process::id();
    // Uptime is not straightforward in std, sys-info might have it?
    // sys_info::boottime() is available.
    let uptime = 0; // sys_info::boottime not reliable on Windows

    let json = json!({
        "pid": pid,
        "uptime": uptime
    });
    string_to_ptr(json.to_string())
}

// --- Time ---

#[unsafe(no_mangle)]
pub extern "C" fn time_sleep(ms: f64) {
    thread::sleep(Duration::from_millis(ms as u64));
}
