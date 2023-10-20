use std::{collections::HashMap, net::SocketAddr};
use uuid::Uuid;

use blake2::{digest::consts::U24, Blake2b, Digest};
use chacha20poly1305::aead::Aead;

use crate::{
    app_state::ClientKeypair,
    crypto::key_exchange::{ECDHKeys, ECDHPubKey, ECDSAPubKey, Signature},
    APPSTATE,
};

type Blake2b192 = Blake2b<U24>;

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
pub enum FrameType {
    #[default]
    Data = 1,
    Init = 0,
}

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    #[default]
    Legacy = 0,
    Kyber = 1,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InitOptions {
    encryption_type: Option<EncryptionType>,
    nonce_secondary_key: Option<bool>,
    status: u8,
}

impl InitOptions {
    pub fn new_with_enc_type(enc_type: EncryptionType) -> InitOptions {
        InitOptions {
            encryption_type: Some(enc_type),
            nonce_secondary_key: Some(true),
            status: 0,
        }
    }

    pub fn nonce_secondary_key(mut self, nonce_sec_key: bool) -> InitOptions {
        self.nonce_secondary_key = Some(nonce_sec_key);
        self
    }

    pub fn status(mut self, status: u8) -> InitOptions {
        self.status = status;
        self
    }

    pub fn encryption_type(mut self, enc_type: EncryptionType) -> InitOptions {
        self.encryption_type = Some(enc_type);
        self
    }

    pub fn get_encryption_type(&self) -> Option<EncryptionType> {
        self.encryption_type
    }

    pub fn get_nonce_secondary_key(&self) -> Option<bool> {
        self.nonce_secondary_key
    }
}

impl Into<Vec<u8>> for InitOptions {
    fn into(self) -> Vec<u8> {
        let enc_type = self.encryption_type.unwrap() as u8;
        let status = self.status;
        let nonce_secondary_key: u8 = if let Some(nonce) = self.nonce_secondary_key {
            match nonce {
                false => 0,
                true => 1,
            }
        } else {
            0
        };
        format!("encryption_type = {enc_type}\u{00ae}status = {status}\u{00ae}nonce_secondary_key = {nonce_secondary_key}\u{00ae}").into_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Options {
    frame_type: FrameType,
    ip_addr: Option<SocketAddr>,
    init_opts: Option<InitOptions>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            frame_type: FrameType::Data,
            ip_addr: APPSTATE
                .try_read()
                .expect("could not acquire read handle on appstate")
                .server_addr,
            init_opts: None,
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

        if self.frame_type == FrameType::Init {
            [
                header_as_string.into_bytes(),
                ip_addr_as_string.into_bytes(),
                self.init_opts.unwrap().into(),
            ]
            .concat()
        } else {
            [
                header_as_string.into_bytes(),
                ip_addr_as_string.into_bytes(),
            ]
            .concat()
        }
    }
}

impl TryFrom<&[u8]> for Options {
    type Error = Box<dyn std::error::Error>;
    fn try_from(options_bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut current_opt_index = 0usize;
        let mut options_map = HashMap::new();

        log::trace!("options bytes {:?}", options_bytes);

        log::trace!("\x1b[38;2;238;171;196mBEGIN OPTION PARSING LOOP!\x1b[1;0m\n");
        while let Some(option_slice) = options_bytes[current_opt_index..]
            .iter()
            .enumerate()
            .find(|(_, ascii_code)| **ascii_code == 174)
            .map(|(index, _)| &options_bytes[current_opt_index..current_opt_index + index])
        {
            log::trace!("\x1b[38;2;108;190;237m");
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

            log::trace!("header: {header_key_str} = {header_value_str}");

            options_map.insert(header_key_str, header_value_str);

            current_opt_index += option_slice.len() + 1;
        }
        log::trace!("\x1b[1;0m");
        log::trace!("\x1b[38;2;238;171;196mEND OF OPTION PARSING LOOP!\x1b[1;0m\n");

        let frame_type = match options_map
            .get("frame_type")
            .expect("frame_type option not sent!")
            .parse::<u8>()
            .expect("frame_type value not a u8")
        {
            0 => FrameType::Init,
            1 => FrameType::Data,
            2u8..=u8::MAX => return Err("frame_type out of bounds".into()),
        };

        let init_opts = if frame_type == FrameType::Init {
            let enc_type = match options_map
                .get("encryption_type")
                .expect("encryption_type flag not found")
                .parse::<u8>()
                .unwrap()
            {
                0 => EncryptionType::Legacy,
                1 => EncryptionType::Kyber,
                2u8..=u8::MAX => return Err("enc_type out of bounds".into()),
            };

            // If not defined, it is off
            let nonce_secondary_key = options_map
                .get("nonce_secondary_key")
                .expect("nonce_secondary_key flag not defined")
                .parse::<u8>()
                .unwrap();
            Some(
                InitOptions::new_with_enc_type(enc_type)
                    .status(0)
                    .nonce_secondary_key(nonce_secondary_key == 1),
            )
        } else {
            None
        };
        let options = Options {
            frame_type,
            ip_addr: if let Some(ip_addr_str) = options_map.get("ip_addr") {
                if let Ok(ip_socket_addr) = ip_addr_str.parse::<SocketAddr>() {
                    Some(ip_socket_addr)
                } else {
                    None
                }
            } else {
                None
            },
            init_opts,
        };

        Ok(options)
    }
}

impl Options {
    pub fn get_frame_type(&self) -> FrameType {
        self.frame_type
    }

    pub fn get_ip_addr(&self) -> Option<SocketAddr> {
        self.ip_addr
    }

    pub fn get_init_opts(&self) -> Option<InitOptions> {
        self.init_opts
    }
}

pub trait Frame {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait ToInitFrame {
    fn to_frame(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

impl ToInitFrame for Vec<u8> {
    fn to_frame(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let options_len = u32::from_be_bytes(self[19..23].try_into()?);
        let options_range = &self[23..23 + options_len as usize];
        let options = Options::try_from(options_range)?;

        if options.get_frame_type() == FrameType::Init {
            InitFrame::default().from_peer(self)
        } else {
            Err("Not a InitFrame".into())
        }
    }
}

pub struct InitFrame {
    pub id: [u8; 3],
    pub uuid: [u8; 16],
    pub options: Options,
    pub ecdsa_pub_key: ECDSAPubKey,
    pub ecdh_pub_key: ECDHPubKey,
    pub ecdh_keys: Option<ECDHKeys>,
    pub ecdh_signature: Signature,
    pub ecdh_pub_nonce_key: Option<ECDHPubKey>,
    pub ecdh_nonce_keys: Option<ECDHKeys>,
}

impl TryFrom<Box<[u8]>> for InitFrame {
    type Error = Box<dyn std::error::Error>;
    fn try_from(frame_bytes: Box<[u8]>) -> Result<InitFrame, Self::Error> {
        let options_len = u32::from_be_bytes(frame_bytes[19..23].try_into().unwrap());
        let options_arr = &frame_bytes[23..23 + options_len as usize];
        let options = Options::try_from(options_arr)?;
        if options.get_frame_type() != FrameType::Init {
            return Err("not a InitFrame".into());
        };

        let id = &frame_bytes[0..=2];
        let uuid = Uuid::from_slice(&frame_bytes[3..=18]).unwrap();
        let body = &frame_bytes[23..];

        let init_vars_slice = &body[options_len as usize..];

        let client_ecdsa_key = ECDSAPubKey::from_sec1_bytes(&init_vars_slice[..97]).unwrap();
        let client_ecdh_key_bytes = &init_vars_slice[97..194];
        let is_second_ecdh_key = options
            .get_init_opts()
            .unwrap()
            .get_nonce_secondary_key()
            .unwrap();
        let (sec_ecdh_pub_key, client_signature) = if is_second_ecdh_key {
            // Client has confirmed they sent another ECDH key.

            let sec_key_bytes = &init_vars_slice[194..291];
            let sec_key = ECDHPubKey::from_sec1_bytes(sec_key_bytes).unwrap();
            (
                Some(sec_key),
                Signature::from_der(&init_vars_slice[291..]).unwrap(),
            )
        } else {
            (None, Signature::from_der(&init_vars_slice[194..]).unwrap())
        };
        //log::trace!("server res: key: {:#?}", client_signature);
        if client_ecdsa_key
            .verify(client_ecdh_key_bytes, &client_signature)
            .is_err()
        {
            log::trace!("SIG FAILED :(");
        }

        let client_ecdh_key = ECDHPubKey::from_sec1_bytes(client_ecdh_key_bytes).unwrap();

        Ok(InitFrame {
            id: id.try_into()?,
            uuid: uuid.into_bytes(),
            options,
            ecdsa_pub_key: client_ecdsa_key,
            ecdh_pub_key: client_ecdh_key,
            ecdh_keys: None,
            ecdh_signature: client_signature,
            ecdh_pub_nonce_key: sec_ecdh_pub_key,
            ecdh_nonce_keys: None,
        })
    }
}

impl Frame for InitFrame {
    fn to_bytes(&self) -> Vec<u8> {
        let options_bytes: Vec<u8> = self.options.into();
        let options_size: u32 = options_bytes.len() as u32;
        if let Some(nonce) = &self.ecdh_pub_nonce_key {
            [
                self.id.as_slice(),
                self.uuid.as_slice(),
                &options_size.to_be_bytes(),
                &options_bytes,
                &self.ecdsa_pub_key.to_bytes(),
                &self.ecdh_pub_key.get_pub_key_to_bytes(),
                &nonce.get_pub_key_to_bytes(),
                &self.ecdh_signature.to_bytes(),
            ]
            .concat()
        } else {
            [
                self.id.as_slice(),
                self.uuid.as_slice(),
                &options_size.to_be_bytes(),
                &options_bytes,
                &self.ecdsa_pub_key.to_bytes(),
                &self.ecdh_pub_key.get_pub_key_to_bytes(),
                &self.ecdh_signature.to_bytes(),
            ]
            .concat()
        }
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
        options.init_opts = Some(
            InitOptions::new_with_enc_type(EncryptionType::Legacy)
                .status(0)
                .nonce_secondary_key(true),
        );
        let ecdsa_pub_key = appstate_r.server_keys.ecdsa.get_pub_key().clone();
        let ecdh_keys = Some(ECDHKeys::init());
        let ecdh_pub_key = ecdh_keys.as_ref().unwrap().get_pub_key();

        let ecdh_nonce_keys = Some(ECDHKeys::init());
        let ecdh_pub_nonce_key = Some(ecdh_nonce_keys.as_ref().unwrap().get_pub_key());

        let ecdh_signature = appstate_r
            .server_keys
            .ecdsa
            .sign(&ecdh_keys.as_ref().unwrap().get_pub_key_to_bytes());

        InitFrame {
            id,
            uuid,
            options,
            ecdsa_pub_key,
            ecdh_pub_key,
            ecdh_keys,
            ecdh_signature,
            ecdh_nonce_keys,
            ecdh_pub_nonce_key,
        }
    }
}

impl InitFrame {
    pub fn from_peer(self, frame_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

        let client_ecdsa_key = ECDSAPubKey::from_sec1_bytes(&init_vars_slice[..97]).unwrap();
        let client_ecdh_key_bytes = &init_vars_slice[97..194];

        // If client sends an additional ECDH key (for the nonce)
        let is_second_ecdh_key = options
            .get_init_opts()
            .unwrap()
            .get_nonce_secondary_key()
            .unwrap();

        let (sec_shared_secret, client_signature, is_nonce) = if is_second_ecdh_key {
            // Client has confirmed they sent another ECDH key.

            let sec_key_bytes = &init_vars_slice[194..291];
            let sec_key = ECDHPubKey::from_sec1_bytes(sec_key_bytes).unwrap();
            let sec_ecdh_keys = self.ecdh_nonce_keys.unwrap();
            let sec_shared_secret = sec_ecdh_keys.gen_shared_secret(&sec_key);
            (
                Some(sec_shared_secret),
                Signature::from_der(&init_vars_slice[291..]).unwrap(),
                true,
            )
        } else {
            (
                None,
                Signature::from_der(&init_vars_slice[194..]).unwrap(),
                false,
            )
        };

        //log::trace!("server res: key: {:#?}", client_signature);
        client_ecdsa_key
            .verify(client_ecdh_key_bytes, &client_signature)
            .expect("signature verification failed :(");

        let client_ecdh_key = ECDHPubKey::from_sec1_bytes(client_ecdh_key_bytes).unwrap();
        let peer_shared_secret = self.ecdh_keys.unwrap().gen_shared_secret(&client_ecdh_key);

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
            .ip(ip_addr_of_peer)
            .ecdh_secondary(sec_shared_secret)
            .uuid(uuid);

        let client_keys = &mut APPSTATE
            .try_write()
            .expect("failed to get write lock")
            .client_keys;

        client_keys.push(client_keypair);

        let options_bytes: Vec<u8> = self.options.into();
        let options_size: u32 = options_bytes.len() as u32;

        if is_nonce {
            Ok([
                self.id.as_slice(),
                self.uuid.as_slice(),
                &options_size.to_be_bytes(),
                &options_bytes,
                &self.ecdsa_pub_key.to_bytes(),
                &self.ecdh_pub_key.get_pub_key_to_bytes(),
                &self.ecdh_pub_nonce_key.unwrap().get_pub_key_to_bytes(),
                &self.ecdh_signature.to_bytes(),
            ]
            .concat())
        } else {
            Ok([
                self.id.as_slice(),
                self.uuid.as_slice(),
                &options_size.to_be_bytes(),
                &options_bytes,
                &self.ecdsa_pub_key.to_bytes(),
                &self.ecdh_pub_key.get_pub_key_to_bytes(),
                &self.ecdh_signature.to_bytes(),
            ]
            .concat())
        }
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

        let mut hasher = Blake2b192::new();
        if let Some(nonce) = &target_keychain.ecdh_secondary {
            log::trace!("encoding with secondary ecdh key");
            hasher.update(nonce.raw_secret_bytes());
        } else {
            hasher.update(shared_secret_bytes)
        }
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

        let mut hasher = Blake2b192::new();
        let res = if let Some(nonce) = &target_keychain.ecdh_secondary {
            log::trace!("decrypting frame with secondary ecdh key");
            hasher.update(nonce.raw_secret_bytes());
            hasher.finalize()
        } else {
            hasher.update(shared_secret_bytes);
            hasher.finalize()
        };
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

        let mut hasher = Blake2b192::new();
        let res = if let Some(nonce) = &target_keychain.ecdh_secondary {
            log::trace!("decrypting frame with secondary ecdh key");
            hasher.update(nonce.raw_secret_bytes());
            hasher.finalize()
        } else {
            hasher.update(shared_secret_bytes);
            hasher.finalize()
        };

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

        let mut hasher = Blake2b192::new();
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

        let mut hasher = Blake2b192::new();
        hasher.update(shared_secret_bytes);
        let res = hasher.finalize();
        log::trace!("len of hash (blake2b96): {:?}", &res.len());
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
