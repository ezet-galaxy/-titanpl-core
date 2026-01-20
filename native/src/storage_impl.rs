use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::fs;
use std::io::Write;

lazy_static! {
    static ref STORAGE: Mutex<HashMap<String, String>> = Mutex::new(load_storage().unwrap_or_default());
}

const STORAGE_FILE: &str = "titan_storage.json";

fn load_storage() -> Result<HashMap<String, String>, String> {
    if let Ok(content) = fs::read_to_string(STORAGE_FILE) {
        let map: HashMap<String, String> = serde_json::from_str(&content).unwrap_or_default();
        return Ok(map);
    }
    Ok(HashMap::new())
}

fn save_storage() -> Result<(), String> {
    let map = STORAGE.lock().map_err(|_| "Storage Lock poisoned".to_string())?;
    let json = serde_json::to_string_pretty(&*map).map_err(|e| e.to_string())?;
    let mut file = fs::File::create(STORAGE_FILE).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

// --- Local Storage ---

pub fn ls_get(key: &str) -> Option<String> {
    let map = STORAGE.lock().ok()?;
    map.get(key).cloned()
}

pub fn ls_set(key: &str, value: &str) -> Result<(), String> {
    {
        let mut map = STORAGE.lock().map_err(|_| "Storage Lock poisoned".to_string())?;
        map.insert(key.to_string(), value.to_string());
    } // Unlock before save to avoid holding lock too long (though save also needs lock? No, save reads lock)
    // Actually save_storage locks it again.
    // Better: update and save in block?
    // Let's optimize:
    // With singleton file, we should probably just lock, update, save.
    // But save_storage implementation above re-locks. I should fix that.
    
    // Quick fix: Do it inline here or refine save_storage helper.
    // Let's refine helper to take reference? No, simple is best.
    // Just lock, insert, release. Then save handles its own lock. consistency window is small but ok for this.
    
    save_storage()
}

pub fn ls_remove(key: &str) -> Result<(), String> {
    {
        let mut map = STORAGE.lock().map_err(|_| "Storage Lock poisoned".to_string())?;
        map.remove(key);
    }
    save_storage()
}

pub fn ls_clear() -> Result<(), String> {
    {
        let mut map = STORAGE.lock().map_err(|_| "Storage Lock poisoned".to_string())?;
        map.clear();
    }
    save_storage()
}

pub fn ls_keys() -> Result<Vec<String>, String> {
    let map = STORAGE.lock().map_err(|_| "Storage Lock poisoned".to_string())?;
    Ok(map.keys().cloned().collect())
}

// --- Sessions ---
// For now, implement sessions in same file or separate?
// Previous implementation put sessions in `sessions` tree in sled.
// Here I can put them in a separate map or prefix keys?
// Let's use prefix "session:ID:" in the same JSON for simplicity?
// Or a separate file "titan_sessions.json"?
// Separate file is cleaner.

lazy_static! {
    static ref SESSIONS: Mutex<HashMap<String, String>> = Mutex::new(load_sessions().unwrap_or_default());
}
const SESSION_FILE: &str = "titan_sessions.json";

fn load_sessions() -> Result<HashMap<String, String>, String> {
    if let Ok(content) = fs::read_to_string(SESSION_FILE) {
        Ok(serde_json::from_str(&content).unwrap_or_default())
    } else {
        Ok(HashMap::new())
    }
}

fn save_sessions() -> Result<(), String> {
    let map = SESSIONS.lock().map_err(|_| "Session Lock poisoned".to_string())?;
    let json = serde_json::to_string(&*map).map_err(|e| e.to_string())?;
    fs::write(SESSION_FILE, json).map_err(|e| e.to_string())
}

pub fn session_set(session_id: &str, key: &str, value: &str) -> Result<(), String> {
    {
        let mut map = SESSIONS.lock().map_err(|_| "Session Lock poisoned".to_string())?;
        let comp_key = format!("{}:{}", session_id, key);
        map.insert(comp_key, value.to_string());
    }
    save_sessions()
}

pub fn session_get(session_id: &str, key: &str) -> Option<String> {
    let map = SESSIONS.lock().ok()?;
    let comp_key = format!("{}:{}", session_id, key);
    map.get(&comp_key).cloned()
}

pub fn session_delete(session_id: &str, key: &str) -> Result<(), String> {
    {
         let mut map = SESSIONS.lock().map_err(|_| "Session Lock poisoned".to_string())?;
         let comp_key = format!("{}:{}", session_id, key);
         map.remove(&comp_key);
    }
    save_sessions()
}

pub fn session_clear(session_id: &str) -> Result<(), String> {
    {
         let mut map = SESSIONS.lock().map_err(|_| "Session Lock poisoned".to_string())?;
         let prefix = format!("{}:", session_id);
         map.retain(|k, _| !k.starts_with(&prefix));
    }
    save_sessions()
}
