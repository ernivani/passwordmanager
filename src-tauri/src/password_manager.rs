use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use dirs_next::config_dir;

#[derive(Error, Debug)]
pub enum PasswordManagerError {
    #[error("Encryption/Decryption error")]
    CryptoError,
    #[error("Item not found")]
    NotFound,
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Invalid master password")]
    InvalidMasterPassword,
    #[error("Password too weak: {0}")]
    WeakPassword(String),
    #[error("Generic error: {0}")]
    Other(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub service: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct PasswordManager {
    database: HashMap<String, PasswordEntry>,
    key: Vec<u8>,
    master_password_hash: Option<Vec<u8>>,
    config_path: PathBuf,
    db_path: PathBuf,
}

impl PasswordManager {
    pub fn new() -> Self {
        let config_dir = config_dir()
            .expect("Failed to get config directory")
            .join("password_manager");

        fs::create_dir_all(&config_dir).expect("Failed to create config directory");
        
        let config_path = config_dir.join("config.dat");
        let db_path = config_dir.join("database.dat");
        
        Self {
            database: HashMap::new(),
            key: vec![0u8; 32],
            master_password_hash: None,
            config_path,
            db_path,
        }
    }

    pub fn has_master_password(&self) -> bool {
        if let Ok(contents) = fs::read(&self.config_path) {
            !contents.is_empty()
        } else {
            false
        }
    }

    fn validate_password_strength(password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }
        if !password.chars().any(|c| c.is_uppercase()) {
            return Err("Password must contain at least one uppercase letter".to_string());
        }
        if !password.chars().any(|c| c.is_lowercase()) {
            return Err("Password must contain at least one lowercase letter".to_string());
        }
        if !password.chars().any(|c| c.is_numeric()) {
            return Err("Password must contain at least one number".to_string());
        }
        if !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err("Password must contain at least one special character".to_string());
        }
        Ok(())
    }

    pub fn create_master_password(&mut self, password: &str) -> Result<(), PasswordManagerError> {
        if let Err(msg) = Self::validate_password_strength(password) {
            return Err(PasswordManagerError::WeakPassword(msg));
        }
        // Generate a new random key
        let mut key = vec![0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| PasswordManagerError::CryptoError)?;

        // Hash the master password
        let password_hash = digest(&SHA256, password.as_bytes()).as_ref().to_vec();

        // Save the hash and encrypted key
        let config_data = serialize_config(&password_hash, &key);
        fs::write(&self.config_path, config_data).map_err(|e| PasswordManagerError::IoError(e.to_string()))?;

        self.key = key;
        self.master_password_hash = Some(password_hash);

        // Initialize empty database
        self.save_database()?;

        Ok(())
    }

    pub fn verify_master_password(&mut self, password: &str) -> Result<(), PasswordManagerError> {
        let contents = fs::read(&self.config_path)
            .map_err(|e| PasswordManagerError::IoError(e.to_string()))?;

        let (stored_hash, key) = deserialize_config(&contents)
            .map_err(|_| PasswordManagerError::CryptoError)?;

        let password_hash = digest(&SHA256, password.as_bytes()).as_ref().to_vec();

        if password_hash != stored_hash {
            return Err(PasswordManagerError::InvalidMasterPassword);
        }

        self.key = key;
        self.master_password_hash = Some(stored_hash);

        // Load the database
        self.load_database()?;

        Ok(())
    }

    fn load_database(&mut self) -> Result<(), PasswordManagerError> {
        if let Ok(encrypted) = fs::read(&self.db_path) {
            if !encrypted.is_empty() {
                let decrypted = self.decrypt_data(&encrypted)?;
                self.database = serde_json::from_slice(&decrypted)
                    .map_err(|e| PasswordManagerError::Other(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn save_database(&self) -> Result<(), PasswordManagerError> {
        let serialized = serde_json::to_vec(&self.database)
            .map_err(|e| PasswordManagerError::Other(e.to_string()))?;
        
        let encrypted = self.encrypt_data(&serialized)?;
        fs::write(&self.db_path, &encrypted)
            .map_err(|e| PasswordManagerError::IoError(e.to_string()))?;
        
        Ok(())
    }

    pub fn add_password(
        &mut self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), PasswordManagerError> {
        if let Err(msg) = Self::validate_password_strength(password) {
            return Err(PasswordManagerError::WeakPassword(msg));
        }
        
        let entry = PasswordEntry {
            service: service.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        };
        
        self.database.insert(service.to_string(), entry);
        self.save_database()?;
        Ok(())
    }

    /// Retrieve a PasswordEntry if it exists.
    pub fn get_password(
        &self,
        service: &str,
    ) -> Result<PasswordEntry, PasswordManagerError> {
        let entry = self
            .database
            .get(service)
            .cloned()
            .ok_or(PasswordManagerError::NotFound)?;
        Ok(entry)
    }

    /// Example encryption function: you’d typically encrypt the entire database, not just a single entry.
    pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, PasswordManagerError> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| PasswordManagerError::CryptoError)?;
        let key = LessSafeKey::new(unbound_key);

        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| PasswordManagerError::CryptoError)?;

        let mut in_out = data.to_vec();
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .map_err(|_| PasswordManagerError::CryptoError)?;

        // Store nonce at the beginning of the ciphertext so we can retrieve it on decrypt
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(&in_out);
        Ok(encrypted)
    }

    /// Example decryption function
    pub fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, PasswordManagerError> {
        if data.len() < 12 {
            return Err(PasswordManagerError::CryptoError);
        }
        let (nonce_slice, ciphertext) = data.split_at(12);
        let nonce: [u8; 12] = nonce_slice.try_into().map_err(|_| PasswordManagerError::CryptoError)?;
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| PasswordManagerError::CryptoError)?;
        let key = LessSafeKey::new(unbound_key);

        let mut in_out = ciphertext.to_vec();
        key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .map_err(|_| PasswordManagerError::CryptoError)?;
        Ok(in_out)
    }

    pub fn get_all_passwords(&self) -> Vec<PasswordEntry> {
        self.database.values().cloned().collect()
    }

    pub fn delete_password(&mut self, service: &str) -> Result<(), PasswordManagerError> {
        if self.database.remove(service).is_none() {
            return Err(PasswordManagerError::NotFound);
        }
        self.save_database()?;
        Ok(())
    }
}

// Helper functions for config serialization
fn serialize_config(hash: &[u8], encrypted_key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&(hash.len() as u32).to_le_bytes());
    result.extend_from_slice(hash);
    result.extend_from_slice(encrypted_key);
    result
}

fn deserialize_config(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    if data.len() < 4 {
        return Err("Invalid config data");
    }
    
    let hash_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + hash_len {
        return Err("Invalid config data");
    }
    
    let hash = data[4..4+hash_len].to_vec();
    let encrypted_key = data[4+hash_len..].to_vec();
    
    Ok((hash, encrypted_key))
}

// Shared state for concurrency in Tauri
pub type SharedManager = Arc<Mutex<PasswordManager>>;
