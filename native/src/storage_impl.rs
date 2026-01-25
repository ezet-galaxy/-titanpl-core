use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};


static STORAGE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
static SESSIONS: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn get_storage() -> &'static RwLock<HashMap<String, String>> {
    STORAGE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn get_sessions() -> &'static RwLock<HashMap<String, String>> {
    SESSIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

// --- Local Storage ---

pub fn ls_get(key: &str) -> Option<String> {
    let map = get_storage().read().ok()?;
    map.get(key).cloned()
}

pub fn ls_set(key: &str, value: &str) -> Result<(), String> {
    let mut map = get_storage().write().map_err(|_| "Storage write lock poisoned".to_string())?;
    map.insert(key.to_string(), value.to_string());
    Ok(())
}

pub fn ls_remove(key: &str) -> Result<(), String> {
    let mut map = get_storage().write().map_err(|_| "Storage write lock poisoned".to_string())?;
    map.remove(key);
    Ok(())
}

pub fn ls_clear() -> Result<(), String> {
    let mut map = get_storage().write().map_err(|_| "Storage write lock poisoned".to_string())?;
    map.clear();
    Ok(())
}

pub fn ls_keys() -> Result<Vec<String>, String> {
    let map = get_storage().read().map_err(|_| "Storage read lock poisoned".to_string())?;
    Ok(map.keys().cloned().collect())
}

// --- Sessions ---

pub fn session_set(session_id: &str, key: &str, value: &str) -> Result<(), String> {
    let mut map = get_sessions().write().map_err(|_| "Session write lock poisoned".to_string())?;
    let comp_key = format!("{}:{}", session_id, key);
    map.insert(comp_key, value.to_string());
    Ok(())
}

pub fn session_get(session_id: &str, key: &str) -> Option<String> {
    let map = get_sessions().read().ok()?;
    let comp_key = format!("{}:{}", session_id, key);
    map.get(&comp_key).cloned()
}

pub fn session_delete(session_id: &str, key: &str) -> Result<(), String> {
    let mut map = get_sessions().write().map_err(|_| "Session write lock poisoned".to_string())?;
    let comp_key = format!("{}:{}", session_id, key);
    map.remove(&comp_key);
    Ok(())
}

pub fn session_clear(session_id: &str) -> Result<(), String> {
    let mut map = get_sessions().write().map_err(|_| "Session write lock poisoned".to_string())?;
    let prefix = format!("{}:", session_id);
    map.retain(|k, _| !k.starts_with(&prefix));
    Ok(())
}
