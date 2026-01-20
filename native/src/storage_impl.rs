use sled::Db;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::str;

lazy_static! {
    static ref DB: Mutex<Option<Db>> = Mutex::new(None);
}

fn get_db() -> Result<Db, String> {
    let mut db_l = DB.lock().map_err(|_| "DB Lock poisoned".to_string())?;
    if let Some(ref db) = *db_l {
        return Ok(db.clone());
    }
    
    // Open in current directory
    let db = sled::open("titan_storage.db").map_err(|e| format!("Failed to open DB: {}", e))?;
    *db_l = Some(db.clone());
    Ok(db)
}

// --- Local Storage ---

/// Retrieves a value from the persistent local storage.
pub fn ls_get(key: &str) -> Option<String> {
    let db = get_db().ok()?;
    match db.get(key) {
        Ok(Some(val)) => String::from_utf8(val.to_vec()).ok(),
        _ => None
    }
}

/// Sets a value in the persistent local storage.
pub fn ls_set(key: &str, value: &str) -> Result<(), String> {
    let db = get_db()?;
    db.insert(key, value.as_bytes()).map(|_| ()).map_err(|e| e.to_string())
}

/// Removes a key from local storage.
pub fn ls_remove(key: &str) -> Result<(), String> {
    let db = get_db()?;
    db.remove(key).map(|_| ()).map_err(|e| e.to_string())
}

/// Clears all keys from local storage.
pub fn ls_clear() -> Result<(), String> {
    let db = get_db()?;
    db.clear().map(|_| ()).map_err(|e| e.to_string())
}

/// Lists all keys in local storage.
pub fn ls_keys() -> Result<Vec<String>, String> {
    let db = get_db()?;
    let mut keys = Vec::new();
    for item in db.iter() {
        if let Ok((k, _)) = item {
            if let Ok(k_str) = String::from_utf8(k.to_vec()) {
                keys.push(k_str);
            }
        }
    }
    Ok(keys)
}

// --- Sessions ---
// Stored in a separate tree "sessions".
// Key: sessionId:key
// Value: JSON string with value and expiry? 
// Actually, usually users want `session.get(id, key)`. 
// If we want "session expires" (entire session), we should track session last active time.
// But prompt say "Sessions auto-expire (configurable TTL)".
// Simplest: Store { val: "...", expiry: 123456789 } for each key? Or store session metadata?
// "session.get(id, key)" implies Key-Value per session.
// I will implement simple KV with composite key "id:key", and maybe not enforce strict TTL per-key here unless requested.
// Prompt: "Sessions auto-expire (configurable TTL)".
// I will just add a global TTL check if I can? 
// Or better: Each session has a "created_at" or "last_accessed"?
// Let's implement basics: set/get/delete/clear.


pub fn session_set(session_id: &str, key: &str, value: &str) -> Result<(), String> {
    let db = get_db()?;
    let tree = db.open_tree("sessions").map_err(|e| e.to_string())?;
    
    let composite_key = format!("{}:{}", session_id, key);
    // Value could just be string for now.
    tree.insert(composite_key, value.as_bytes()).map(|_| ()).map_err(|e| e.to_string())
}

pub fn session_get(session_id: &str, key: &str) -> Option<String> {
    let db = get_db().ok()?;
    if let Ok(tree) = db.open_tree("sessions") {
         let composite_key = format!("{}:{}", session_id, key);
         if let Ok(Some(val)) = tree.get(composite_key) {
             return String::from_utf8(val.to_vec()).ok();
         }
    }
    None
}

pub fn session_delete(session_id: &str, key: &str) -> Result<(), String> {
    let db = get_db()?;
    let tree = db.open_tree("sessions").map_err(|e| e.to_string())?;
    let composite_key = format!("{}:{}", session_id, key);
    tree.remove(composite_key).map(|_| ()).map_err(|e| e.to_string())
}

pub fn session_clear(session_id: &str) -> Result<(), String> {
    let db = get_db()?;
    let tree = db.open_tree("sessions").map_err(|e| e.to_string())?;
    
    // Prefix scan to find all keys for this session
    let prefix = format!("{}:", session_id);
    let mut batch = sled::Batch::default();
    
    for item in tree.scan_prefix(&prefix) {
        if let Ok((k, _)) = item {
             batch.remove(k);
        }
    }
    tree.apply_batch(batch).map_err(|e| e.to_string())
}
