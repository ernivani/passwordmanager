#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod password_manager;
use password_manager::{PasswordEntry, PasswordManager, SharedManager};

use std::sync::{Arc, Mutex};
use tauri::command;

#[command]
fn add_password(
    state: tauri::State<SharedManager>,
    service: String,
    username: String,
    password: String,
) -> Result<(), String> {
    let mut manager = state.lock().unwrap();
    manager
        .add_password(&service, &username, &password)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[command]
fn get_password(
    state: tauri::State<SharedManager>,
    service: String,
) -> Result<PasswordEntry, String> {
    let manager = state.lock().unwrap();
    manager.get_password(&service).map_err(|e| e.to_string())
}

#[command]
fn create_master_password(
    state: tauri::State<SharedManager>,
    password: String,
) -> Result<(), String> {
    let mut manager = state.lock().unwrap();
    manager
        .create_master_password(&password)
        .map_err(|e| e.to_string())
}

#[command]
fn verify_master_password(
    state: tauri::State<SharedManager>,
    password: String,
) -> Result<(), String> {
    let mut manager = state.lock().unwrap();
    manager
        .verify_master_password(&password)
        .map_err(|e| e.to_string())
}

#[command]
fn has_master_password(state: tauri::State<SharedManager>) -> bool {
    let manager = state.lock().unwrap();
    manager.has_master_password()
}

#[command]
fn get_all_passwords(state: tauri::State<SharedManager>) -> Result<Vec<PasswordEntry>, String> {
    let manager = state.lock().unwrap();
    Ok(manager.get_all_passwords())
}

#[command]
fn delete_password(state: tauri::State<SharedManager>, service: String) -> Result<(), String> {
    let mut manager = state.lock().unwrap();
    manager
        .delete_password(&service)
        .map_err(|e| e.to_string())
}

fn main() {
    // Create our shared manager instance
    let manager = Arc::new(Mutex::new(PasswordManager::new()));

    tauri::Builder::default()
        // Manage state so we can access it from commands
        .manage(manager)
        // Register our Tauri commands
        .invoke_handler(tauri::generate_handler![
            add_password,
            get_password,
            create_master_password,
            verify_master_password,
            has_master_password,
            get_all_passwords,
            delete_password
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
