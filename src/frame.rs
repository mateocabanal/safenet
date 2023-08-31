use local_ip_address::local_ip;
use p384::ecdsa::signature::Signer;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use uuid::Uuid;

use blake2::{digest::consts::U12, Blake2b, Digest};
use chacha20poly1305::aead::Aead;
use p384::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};

use crate::{app_state::ClientKeypair, crypto::key_exchange::ECDHKeys, APPSTATE};

type Blake2b96 = Blake2b<U12>;

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
pub enum FrameType {
    #[default]
    Data = 1,
    Init = 0,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Options {
    frame_type: FrameType,
    ip_addr: Option<SocketAddr>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            frame_type: FrameType::Data,
            ip_addr: APPSTATE
                .try_read()
                .expect("could not acquire read handle on appstate")
                .server_addr,
        }
    }
}

impl Into<Vec<u8>> for Options {
    fn into(self) -> Vec<u8> {
        let header_as_string = format!("frame_type = {}\u{00ae}", self.frame_type as u8);
        let ip_addr_as_string = if let Some(addr) = self.ip_addr {
            format!("ip_addr = {}\u{00ae}", addr)
        } else {
            "".to_string()
        };

        [
            header_as_string.into_bytes(),
            ip_addr_as_string.into_bytes(),
        ]
        .concat()
    }
}

impl TryFrom<&[u8]> for Options {
    type Error = Box<dyn std::error::Error>;
    fn try_from(options_bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut current_opt_index = 0usize;
        let mut options_map = HashMap::new();

        #[cfg(test)]
        {
            println!("options bytes {:?}", options_bytes);
        }

        while let Some(option_slice) = options_bytes[current_opt_index..]
            .iter()
            .enumerate()
            .find(|(_, ascii_code)| **ascii_code == 174)
            .map(|(index, _)| &options_bytes[current_opt_index..current_opt_index + index])
        {
            #[cfg(test)]
            println!(
                "length of option, current_opt_index: {:?}, {}",
                option_slice, current_opt_index
            );

            let equal_sign_pos = option_slice
                .iter()
                .position(|ascii_code| *ascii_code == 61)
                .expect("could not find '=' in option");
            let header_key = &option_slice[..equal_sign_pos];
            let header_value = &option_slice[equal_sign_pos + 1..option_slice.len() - 1];

            let header_key_str = std::str::from_utf8(header_key)
                .expect("not a valid str")
                .trim()
                .to_string();

            let header_value_str = std::str::from_utf8(header_value)
                .expect("not a valid value str")
                .trim()
                .to_string();

            #[cfg(test)]
            {
                println!("header: {header_key_str} = {header_value_str}");
            }

            options_map.insert(header_key_str, header_value_str);

            current_opt_index += option_slice.len() + 1;
        }
        let options = Options {
            frame_type: match options_map
                .get("frame_type")
                .expect("frame_type option not sent!")
                .parse::<u8>()
                .expect("frame_type value not a u8")
            {
                0 => FrameType::Init,
                1 => FrameType::Data,
                2u8..=u8::MAX => return Err("frame_type out of bounds".into()),
            },
            ip_addr: if let Some(ip_addr_str) = options_map.get("ip_addr") {
                if let Ok(ip_socket_addr) = ip_addr_str.parse::<SocketAddr>() {
                    Some(ip_socket_addr)
                } else {
                    None
                }
            } else {
                None
            },
        };

        Ok(options)
    }
}

pub trait Frame {
    fn to_bytes(&self) -> Vec<u8>;
}

pub struct InitFrame {
    pub id: [u8; 3],
    pub uuid: [u8; 16],
    pub options: Options,
    pub ecdsa_pub_key: VerifyingKey,
    pub ecdh_keys: ECDHKeys,
    pub ecdh_signature: Signature,
}

impl Frame for InitFrame {
    fn to_bytes(&self) -> Vec<u8> {
        let options_bytes: Vec<u8> = self.options.into();
        let options_size: u32 = options_bytes.len() as u32;
        [
            self.id.as_slice(),
            self.uuid.as_slice(),
            &options_size.to_be_bytes(),
            &options_bytes,
            &self.ecdsa_pub_key.to_encoded_point(true).to_bytes(),
            &self.ecdh_keys.pub_key.to_encoded_point(true).to_bytes(),
            &self.ecdh_signature.to_der().to_bytes(),
        ]
        .concat()
    }
}

#[allow(clippy::field_reassign_with_default)]
impl Default for InitFrame {
    fn default() -> InitFrame {
        let appstate_r = APPSTATE
            .try_read()
            .expect("could not get read handle on appstate");
        let id = appstate_r.user_id;
        let uuid = appstate_r.uuid.into_bytes();

        let mut options = Options::default();
        options.frame_type = FrameType::Init;
        let ecdsa_pub_key = appstate_r.server_keys.ecdsa.pub_key;
        let ecdh_keys = ECDHKeys::init();
        let ecdh_signature: Signature = appstate_r
            .server_keys
            .ecdsa
            .priv_key
            .sign(ecdh_keys.pub_key.to_encoded_point(true).as_bytes());

        InitFrame {
            id,
            uuid,
            options,
            ecdsa_pub_key,
            ecdh_keys,
            ecdh_signature,
        }
    }
}

impl InitFrame {
    pub fn from_peer(&self, frame_bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let id = &frame_bytes[0..=2];
        let uuid = Uuid::from_slice(&frame_bytes[3..=18]).unwrap();
        let options_len = u32::from_be_bytes(frame_bytes[19..=22].try_into()?);

        let body = &frame_bytes[23..];

        // PERF: Must wait until "slice_first_last_chunk" feature is stablized
        // in order to use arrays instead
        let options_bytes = &body[..options_len as usize];

        let options = Options::try_from(options_bytes)?;

        let ip_addr_of_peer = options.ip_addr;
        let init_vars_slice = &body[options_len as usize..];

        let client_ecdsa_key = VerifyingKey::from_sec1_bytes(&init_vars_slice[0..=48]).unwrap();
        let client_ecdh_key_bytes = &init_vars_slice[49..=97];
        let client_signature = Signature::from_der(&init_vars_slice[98..]).unwrap();
        //log::trace!("server res: key: {:#?}", client_signature);
        if client_ecdsa_key
            .verify(client_ecdh_key_bytes, &client_signature)
            .is_err()
        {
            log::trace!("SIG FAILED :(");
        }

        let client_ecdh_key = PublicKey::from_sec1_bytes(client_ecdh_key_bytes).unwrap();
        let peer_shared_secret = self.ecdh_keys.priv_key.diffie_hellman(&client_ecdh_key);

        log::trace!(
            "client: secret: {:#?}",
            &peer_shared_secret.raw_secret_bytes()
        );

        log::trace!("added uuid to clientkeypair: {}", &uuid);

        let is_preexisting = APPSTATE
            .read()
            .expect("failed to get read lock")
            .client_keys
            .iter()
            .position(|i| i.uuid == uuid);

        if let Some(s) = is_preexisting {
            APPSTATE
                .write()
                .expect("failed to get write lock")
                .client_keys
                .remove(s);
        }

        let client_keypair = ClientKeypair::new()
            .id(std::str::from_utf8(id)
                .expect("failed to parse id")
                .to_string())
            .ecdsa(client_ecdsa_key)
            .ecdh(peer_shared_secret)
            .uuid(uuid);

        let client_keys = &mut APPSTATE
            .try_write()
            .expect("failed to get write lock")
            .client_keys;

        if let Some(ip_addr) = ip_addr_of_peer {
            client_keys.push(client_keypair.ip(ip_addr));
        } else {
            client_keys.push(client_keypair);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DataFrame {
    pub id: Option<[u8; 3]>,
    pub uuid: Option<[u8; 16]>,
    pub body: Box<[u8]>,
    pub options: Options,
}

// PERF: When feature `new_uninit` is stablized,
// we will replace `Box::default()`
#[allow(clippy::derivable_impls)]
impl Default for DataFrame {
    fn default() -> Self {
        DataFrame {
            id: None,
            uuid: None,
            body: Box::default(),
            options: Options::default(),
        }
    }
}

impl Frame for DataFrame {
    fn to_bytes(&self) -> Vec<u8> {
        let options_bytes: Vec<u8> = self.options.into();
        let options_size: u32 = options_bytes.len() as u32;
        [
            self.id.unwrap().as_slice(),
            self.uuid.unwrap().as_slice(),
            &options_size.to_be_bytes(),
            &options_bytes,
            &self.body,
        ]
        .concat()
    }
}

impl DataFrame {
    pub fn new<'a, T: Into<&'a [u8]>>(input: T) -> Self {
        let id = Some(APPSTATE.try_read().unwrap().user_id);
        let uuid = Some(APPSTATE.try_read().unwrap().uuid.into_bytes());
        let slice = input.into();
        let body = slice.into();
        DataFrame {
            id,
            uuid,
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

        let mut hasher = Blake2b96::new();
        hasher.update(shared_secret_bytes);
        let res = hasher.finalize();
        let encrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .encrypt(generic_array::GenericArray::from_slice(&res), &*self.body)
            .unwrap();

        self.id = Some(app_state.user_id);
        self.uuid = Some(app_state.uuid.into_bytes());
        self.body = encrypted_body.into_boxed_slice();

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

        let mut hasher = Blake2b96::new();
        hasher.update(shared_secret_bytes);
        let res = hasher.finalize();
        let encrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .encrypt(generic_array::GenericArray::from_slice(&res), &*self.body)
            .unwrap();

        self.id = Some(app_state.user_id);
        self.uuid = Some(app_state.uuid.into_bytes());
        self.body = encrypted_body.into_boxed_slice();

        Ok(())
    }

    pub fn decode_frame(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let target_uuid = Uuid::from_bytes(self.uuid.unwrap());
        log::trace!("target_uuid: {target_uuid}");

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

        let mut hasher = Blake2b96::new();
        hasher.update(shared_secret_bytes);
        let res = hasher.finalize();
        let decrypted_body = target_keychain
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .decrypt(generic_array::GenericArray::from_slice(&res), &*self.body);
        match decrypted_body {
            Ok(body) => {
                self.body = body.into_boxed_slice();
                Ok(())
            }
            Err(e) => {
                log::error!("{e}");
                Err("failed to decrypt body".into())
            }
        }
    }
}

#[cfg(test)]
impl DataFrame {
    pub(crate) fn encrypt_frame_with_keypair(
        &mut self,
        keypair: &ClientKeypair,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let shared_secret_bytes = keypair
            .ecdh
            .as_ref()
            .ok_or("failed to get ecdh")?
            .raw_secret_bytes();

        let mut hasher = Blake2b96::new();
        hasher.update(shared_secret_bytes);
        let res = hasher.finalize();
        let encrypted_body = keypair
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .encrypt(generic_array::GenericArray::from_slice(&res), &*self.body)
            .expect("body decryption failed");

        self.id = Some(keypair.id.as_ref().unwrap().as_bytes().try_into().unwrap());
        self.uuid = Some(keypair.uuid.into_bytes());
        self.body = encrypted_body.into_boxed_slice();
        Ok(())
    }

    pub(crate) fn decode_frame_from_keypair(
        &mut self,
        keypair: &ClientKeypair,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let shared_secret_bytes = keypair
            .ecdh
            .as_ref()
            .ok_or("failed to get ecdh")?
            .raw_secret_bytes();

        let mut hasher = Blake2b96::new();
        hasher.update(shared_secret_bytes);
        let res = hasher.finalize();
        let decrypted_body = keypair
            .chacha
            .as_ref()
            .unwrap()
            .cipher
            .decrypt(generic_array::GenericArray::from_slice(&res), &*self.body)
            .expect("body decryption failed");

        self.body = decrypted_body.into_boxed_slice();
        Ok(())
    }
}

impl TryFrom<Box<[u8]>> for DataFrame {
    type Error = String;
    fn try_from(frame_slice: Box<[u8]>) -> Result<DataFrame, String> {
        log::trace!("size of frame: {}", frame_slice.len());
        let id = frame_slice[0..=2].try_into().unwrap();
        let uuid = frame_slice[3..=18].try_into().unwrap();
        let options_len = u32::from_be_bytes(frame_slice[19..=22].try_into().unwrap());
        let options = Options::try_from(&frame_slice[23..23 + options_len as usize]).unwrap();
        let body = frame_slice[23 + options_len as usize..].into();

        if std::str::from_utf8(&frame_slice[0..=2]).is_err() {
            return Err("id is not a valid string".to_owned());
        };

        let id = Some(id);
        let uuid = Some(uuid);

        Ok(DataFrame {
            id,
            uuid,
            body,
            options,
        })
    }
}
//impl TryFrom<&Vec<u8>> for DataFrame {
//    type Error = String;
//    fn try_from(input: &Vec<u8>) -> Result<DataFrame, String> {
//        let frame_slice = input.as_slice();
//        let id = frame_slice[0..=2].try_into().unwrap();
//        let uuid = frame_slice[3..=18].try_into().unwrap();
//        let body = frame_slice[19..].to_vec();
//
//        if std::str::from_utf8(&frame_slice[0..=3]).is_err() {
//            return Err("id is not a valid string".to_owned());
//        };
//
//        let id = Some(id);
//        let uuid = Some(uuid);
//
//        Ok(DataFrame {
//            id,
//            uuid,
//            body,
//            options: Options::default(),
//        })
//    }
//}
