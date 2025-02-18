use wasm_bindgen::prelude::*;
use sha2::{Sha256, Digest};
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::Rng;
use serde::{Serialize, Deserialize};
use base64::{encode, decode};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Note {
    id: String,
    encrypted_content: String,
    timestamp: u64,
    previous_hash: String,
    hash: String,
}

#[wasm_bindgen]
pub struct Blockchain {
    chain: Vec<Note>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl Blockchain {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Blockchain {
        let secret_key = rand::thread_rng().gen::<[u8; 16]>().to_vec();
        let genesis_note = Note {
            id: "genesis".to_string(),
            encrypted_content: "Genesis Block".to_string(),
            timestamp: 0,
            previous_hash: String::new(),
            hash: String::new(),
        };
        Blockchain {
            chain: vec![genesis_note],
            secret_key,
        }
    }

    pub fn encrypt_content(&self, content: &str) -> String {
        let cipher = Aes128Cbc::new_from_slices(&self.secret_key, &self.secret_key).unwrap();
        let encrypted_data = cipher.encrypt_vec(content.as_bytes());
        encode(encrypted_data)
    }

    pub fn decrypt_content(&self, encrypted: &str) -> String {
        let cipher = Aes128Cbc::new_from_slices(&self.secret_key, &self.secret_key).unwrap();
        let decrypted_data = cipher.decrypt_vec(&decode(encrypted).unwrap()).unwrap();
        String::from_utf8(decrypted_data).unwrap()
    }

    pub fn add_note(&mut self, content: String) {
        let encrypted_content = self.encrypt_content(&content);
        let timestamp = js_sys::Date::now() as u64;
        let previous_hash = self.chain.last().unwrap().hash.clone();
        
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", encrypted_content, previous_hash));
        let hash = format!("{:x}", hasher.finalize());

        let note = Note {
            id: timestamp.to_string(),
            encrypted_content,
            timestamp,
            previous_hash,
            hash,
        };

        self.chain.push(note);
    }

    pub fn get_notes(&self) -> JsValue {
        JsValue::from_serde(&self.chain).unwrap()
    }

    pub fn decrypt_notes(&self) -> JsValue {
        let decrypted: Vec<String> = self.chain.iter()
            .map(|note| self.decrypt_content(&note.encrypted_content))
            .collect();
        JsValue::from_serde(&decrypted).unwrap()
    }
}
