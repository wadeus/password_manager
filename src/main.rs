use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use rand::Rng;
use base64::{encode, decode};
use sha2::{Sha256, Digest};
use rpassword::read_password;

const DATA_FILE: &str = "passwords.json";
const KEY_FILE: &str = "key.bin";
const PASSWORD_FILE: &str = "password_hash.bin";

#[derive(Serialize, Deserialize)]
struct PasswordManager {
    passwords: HashMap<String, String>,
}

impl PasswordManager {
    fn new() -> Self {
        PasswordManager {
            passwords: HashMap::new(),
        }
    }

    fn add_password(&mut self, name: String, password: String) {
        self.passwords.insert(name, password);
    }

    fn get_password(&self, name: &str) -> Option<&String> {
        self.passwords.get(name)
    }

    fn remove_password(&mut self, name: &str) {
        self.passwords.remove(name);
    }

    fn save(&self, key: &[u8; 32]) -> io::Result<()> {
        let json = serde_json::to_string(&self).unwrap();
        let cipher = Aes256GcmSiv::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(b"unique nonce");
        let ciphertext = cipher.encrypt(nonce, json.as_bytes()).expect("encryption failure!");
        let encoded = encode(&ciphertext);
        fs::write(DATA_FILE, encoded)?;
        Ok(())
    }

    fn load(key: &[u8; 32]) -> io::Result<Self> {
        if let Ok(data) = fs::read_to_string(DATA_FILE) {
            let cipher = Aes256GcmSiv::new(Key::from_slice(key));
            let nonce = Nonce::from_slice(b"unique nonce");
            let decoded = decode(&data).unwrap();
            let decrypted = cipher.decrypt(nonce, decoded.as_ref()).expect("decryption failure!");
            let json = String::from_utf8(decrypted).unwrap();
            let manager: PasswordManager = serde_json::from_str(&json).unwrap();
            Ok(manager)
        } else {
            Ok(PasswordManager::new())
        }
    }
}

fn main() {
    if !fs::metadata(PASSWORD_FILE).is_ok() {
        println!("No password found. Set a new password:");
        let password = read_password().unwrap();
        let hashed_password = hash_password(&password);
        fs::write(PASSWORD_FILE, hashed_password).expect("Unable to save password hash");
        println!("Password set successfully!");
    } else {
        println!("Enter your password:");
        let password = read_password().unwrap();
        let stored_hash = fs::read(PASSWORD_FILE).expect("Unable to read password hash");
        if hash_password(&password) != stored_hash {
            println!("Incorrect password!");
            return;
        }
        println!("Password authenticated successfully!");
    }

    let key = if let Ok(key_data) = fs::read(KEY_FILE) {
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data);
        key
    } else {
        let key: [u8; 32] = rand::thread_rng().gen();
        fs::write(KEY_FILE, &key).expect("Unable to save key");
        key
    };

    let mut manager = PasswordManager::load(&key).expect("Failed to load passwords");

    loop {
        println!("1. Add Password");
        println!("2. Get Password");
        println!("3. Remove Password");
        println!("4. Save and Exit");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read line");
        let choice: u32 = choice.trim().parse().expect("Please type a number!");

        match choice {
            1 => {
                let mut name = String::new();
                let mut password = String::new();

                println!("Enter name:");
                io::stdin().read_line(&mut name).expect("Failed to read line");
                println!("Enter password:");
                io::stdin().read_line(&mut password).expect("Failed to read line");

                manager.add_password(name.trim().to_string(), password.trim().to_string());
            }
            2 => {
                let mut name = String::new();

                println!("Enter name:");
                io::stdin().read_line(&mut name).expect("Failed to read line");

                if let Some(password) = manager.get_password(name.trim()) {
                    println!("Password: {}", password);
                } else {
                    println!("Password not found");
                }
            }
            3 => {
                let mut name = String::new();

                println!("Enter name:");
                io::stdin().read_line(&mut name).expect("Failed to read line");

                manager.remove_password(name.trim());
            }
            4 => {
                manager.save(&key).expect("Failed to save passwords");
                break;
            }
            _ => println!("Invalid choice!"),
        }
    }
}

fn hash_password(password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}
