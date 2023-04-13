use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chacha20poly1305::aead::Aead;

use crate::APPSTATE;

#[derive(Debug, Clone)]
pub struct DataFrame {
    pub id: [u8; 3],
    pub uuid: [u8; 16],
    pub body: Vec<u8>,
}

impl DataFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.id.as_slice(), self.uuid.as_slice(), &self.body].concat()
    }

    pub fn encode_frame(
        &mut self,
        target_uuid: uuid::Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app_state = APPSTATE.read()?;
        let target_keychain = app_state
            .client_keys
            .iter()
            .find(|i| i.uuid == target_uuid)
            .ok_or("could not find client keys")?;
        let shared_secret_bytes = target_keychain
            .ecdh
            .as_ref()
            .ok_or("failed to get ecdh")?
            .raw_secret_bytes();

        let mut hasher = Blake2bVar::new(12).unwrap();
        let mut buf = [0u8; 12];
        hasher.update(&shared_secret_bytes);
        hasher.finalize_variable(&mut buf).unwrap();
        let encrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .encrypt(generic_array::GenericArray::from_slice(&buf), self.body.as_slice())
            .unwrap();

        self.body = encrypted_body;

        Ok(())
    }

    pub fn decode_frame(&mut self, target_uuid: uuid::Uuid) -> Result<(), Box<dyn std::error::Error>> {
        let app_state = APPSTATE.read()?;
        let target_keychain = app_state
            .client_keys
            .iter()
            .find(|i| i.uuid == target_uuid)
            .ok_or("could not find client keys")?;
        let shared_secret_bytes = target_keychain
            .ecdh
            .as_ref()
            .ok_or("failed to get ecdh")?
            .raw_secret_bytes();

        let mut hasher = Blake2bVar::new(12).unwrap();
        let mut buf = [0u8; 12];
        hasher.update(&shared_secret_bytes);
        hasher.finalize_variable(&mut buf).unwrap();
        let decrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .decrypt(generic_array::GenericArray::from_slice(&buf), self.body.as_slice())
            .unwrap();

        self.body = decrypted_body;

        Ok(())
    }
}
