use std::net::SocketAddr;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chacha20poly1305::aead::Aead;
use p384::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    PublicKey,
};

use crate::APPSTATE;

#[derive(Debug, Clone)]
pub enum FrameType {
    Data,
    Init,
}

#[derive(Clone, Debug)]
pub struct InitFrameOpts {
    ecdsa_pub_key: VerifyingKey,
    ecdh_pub_key: PublicKey,
}
#[derive(Debug, Clone)]
pub struct DataFrame {
    pub id: Option<[u8; 3]>,
    pub uuid: Option<[u8; 16]>,
    pub body: Vec<u8>,
    pub frame_type: Option<FrameType>,
    pub init_frame_opts: Option<InitFrameOpts>,
}

#[allow(clippy::derivable_impls)]
impl Default for DataFrame {
    fn default() -> Self {
        DataFrame {
            id: None,
            uuid: None,
            body: vec![],
            frame_type: None,
            init_frame_opts: None
        }
    }
}

impl DataFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.id.unwrap().as_slice(),
            self.uuid.unwrap().as_slice(),
            &self.body,
        ]
        .concat()
    }

    pub fn get_init_settings(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let body = self.body.as_slice();
        let ecdsa_pub_key_bytes = &body[0..=48];
        let ecdh_pub_key_bytes = &body[49..=97];
        let sig_bytes = &body[98..];

        let ecdsa_pub_key = VerifyingKey::from_sec1_bytes(ecdsa_pub_key_bytes)?;
        let signature = Signature::from_der(sig_bytes)?;

        if ecdsa_pub_key.verify(ecdh_pub_key_bytes, &signature).is_err() {
            return Err("failed to verify ecdh key".into());
        }

        let ecdh_pub_key = PublicKey::from_sec1_bytes(ecdsa_pub_key_bytes)?;
        let shared_secret = APPSTATE.read()?.server_keys.ecdh.priv_key.diffie_hellman(&ecdh_pub_key);


        Ok(())
    }

    pub fn new(body: Vec<u8>) -> Self {
        DataFrame {
            body,
            ..Default::default()
        }
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
        hasher.update(shared_secret_bytes);
        hasher.finalize_variable(&mut buf).unwrap();
        let encrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .encrypt(
                generic_array::GenericArray::from_slice(&buf),
                self.body.as_slice(),
            )
            .unwrap();

        self.id = Some(app_state.user_id);
        self.uuid = Some(*app_state.uuid.as_bytes());
        self.body = encrypted_body;

        Ok(())
    }

    pub fn encode_frame_with_addr(
        &mut self,
        target_peer: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app_state = APPSTATE.read()?;
        log::debug!("keychain: {:#?}", app_state.client_keys);
        let target_keychain = app_state
            .client_keys
            .iter()
            .filter(|i| i.ip.is_some())
            .find(|i| i.ip.unwrap() == target_peer)
            .ok_or("could not find client keys")?;
        let shared_secret_bytes = target_keychain
            .ecdh
            .as_ref()
            .ok_or("failed to get ecdh")?
            .raw_secret_bytes();

        let mut hasher = Blake2bVar::new(12).unwrap();
        let mut buf = [0u8; 12];
        hasher.update(shared_secret_bytes);
        hasher.finalize_variable(&mut buf).unwrap();
        let encrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .encrypt(
                generic_array::GenericArray::from_slice(&buf),
                self.body.as_slice(),
            )
            .unwrap();

        self.id = Some(app_state.user_id);
        self.uuid = Some(*app_state.uuid.as_bytes());
        self.body = encrypted_body;

        Ok(())
    }

    pub fn decode_frame(
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
        hasher.update(shared_secret_bytes);
        hasher.finalize_variable(&mut buf).unwrap();
        let decrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .decrypt(
                generic_array::GenericArray::from_slice(&buf),
                self.body.as_slice(),
            )
            .unwrap();

        self.body = decrypted_body;

        Ok(())
    }
}

impl TryFrom<Vec<u8>> for DataFrame {
    type Error = String;
    fn try_from(input: Vec<u8>) -> Result<DataFrame, String> {
        let frame_slice = input.as_slice();
        let id = frame_slice[0..=2].try_into().unwrap();
        let uuid = frame_slice[3..=18].try_into().unwrap();
        let body = frame_slice[19..].to_vec();

        if std::str::from_utf8(&frame_slice[0..=3]).is_err() {
            return Err("id is not a valid string".to_owned());
        };

        let id = Some(id);
        let uuid = Some(uuid);

        Ok(DataFrame {
            id,
            uuid,
            body,
            frame_type: None,
            init_frame_opts: None,
        })
    }
}

impl TryFrom<&Vec<u8>> for DataFrame {
    type Error = String;
    fn try_from(input: &Vec<u8>) -> Result<DataFrame, String> {
        let frame_slice = input.as_slice();
        let id = frame_slice[0..=2].try_into().unwrap();
        let uuid = frame_slice[3..=18].try_into().unwrap();
        let body = frame_slice[19..].to_vec();

        if std::str::from_utf8(&frame_slice[0..=3]).is_err() {
            return Err("id is not a valid string".to_owned());
        };

        let id = Some(id);
        let uuid = Some(uuid);

        Ok(DataFrame {
            id,
            uuid,
            body,
            frame_type: None,
            init_frame_opts: None,
        })
    }
}
