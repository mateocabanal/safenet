//! The `frame` module contains code relevent to the parsing of Frames.
//! As of the time of writing, the Safenet spec defines two types of Frames,
//! InitFrames and DataFrames.
pub const KYBER_PUBKEY_INDEX: usize = pqc_dilithium::PUBLICKEYBYTES;
pub const KYBER_PUBKEY_INDEX2: usize = KYBER_PUBKEY_INDEX + pqc_kyber::KYBER_PUBLICKEYBYTES;
pub const DITH_SIG_INDEX: usize = KYBER_PUBKEY_INDEX2 + pqc_kyber::KYBER_PUBLICKEYBYTES;
pub const CIPHERTEXT_INDEX: usize = DITH_SIG_INDEX + pqc_dilithium::SIGNBYTES;
pub const NONCE_CIPHERTEXT_INDEX: usize = CIPHERTEXT_INDEX + pqc_kyber::KYBER_CIPHERTEXTBYTES;
use crate::{
    crypto::dilithium::DilithiumPubKey,
    crypto::{KeyNeg, PubKey},
    options::Options,
};

use std::net::SocketAddr;
use uuid::Uuid;

use blake2::{digest::consts::U24, Blake2b, Digest};
use chacha20poly1305::aead::Aead;

use crate::crypto::kyber::KyberDithCipher;
use crate::{
    app_state::ClientKeypair,
    crypto::key_exchange::{ECDHKeys, ECDHPubKey, ECDSAPubKey, Signature},
    APPSTATE,
};

type Blake2b192 = Blake2b<U24>;

/// Used to determine frame type of given frame
#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
pub enum FrameType {
    #[default]
    Data = 1,
    Init = 0,
}

/// Used to determine encryption type for
#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    #[default]
    Legacy = 0,
    Kyber = 1,
    KyberDith = 2,
}

/// A specific set of Options only available to InitFrame's
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InitOptions {
    encryption_type: Option<EncryptionType>,
    nonce_secondary_key: Option<bool>,
    status: u8,
}

impl InitOptions {
    /// A feature to be fully implemented in the future. When Safenet supports different encryption
    /// standards, this will be used. As of now `EncryptionType::Legacy` is the only encryption
    /// type
    pub fn new_with_enc_type(enc_type: EncryptionType) -> InitOptions {
        InitOptions {
            encryption_type: Some(enc_type),
            nonce_secondary_key: Some(true),
            status: 0,
        }
    }

    /// Determines whether or not to include a secondary ECDH key for a secure nonce.
    /// This is true by default (should never want this false, as Safenet will rely on using a hash
    /// of the sent frame if no secondary ECDH key is sent)
    pub fn nonce_secondary_key(mut self, nonce_sec_key: bool) -> InitOptions {
        self.nonce_secondary_key = Some(nonce_sec_key);
        self
    }

    /// Status of encryption. Some protocols will require multiple InitFrames.
    /// As of now, the default encryption type does not need more than 1 InitFrame.
    pub fn status(mut self, status: u8) -> InitOptions {
        self.status = status;
        self
    }

    /// Pretty self-explanitory, as of now there is only one encryption protocol in use.
    /// Post-Quantum Encryption will be added in the future.
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

    pub fn get_status(&self) -> u8 {
        self.status
    }
}

#[allow(clippy::from_over_into)]
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

pub trait Frame {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes<T>(bytes: T) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: AsRef<[u8]>,
        Self: Sized;
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

/// As the name suggests, this is indeed an InitFrame
pub struct InitFrame {
    pub id: [u8; 3],
    pub uuid: [u8; 16],
    pub options: Options,
    pub sig_pub_key: Box<dyn PubKey>,
    pub keyneg_pub_key: Box<[u8]>,
    pub keyneg_keys: Option<Box<dyn KeyNeg>>,
    pub keyneg_signature: Vec<u8>,
    pub nonce_pub_key: Option<Box<[u8]>>,
    pub nonce_keyneg_keys: Option<Box<dyn KeyNeg>>,
}

impl TryFrom<&[u8]> for InitFrame {
    type Error = Box<dyn std::error::Error>;
    fn try_from(frame_bytes: &[u8]) -> Result<InitFrame, Self::Error> {
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
                Some(sec_key.get_pub_key_to_bytes().into_boxed_slice()),
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

        let client_ecdh_key = Box::new(ECDHPubKey::from_sec1_bytes(client_ecdh_key_bytes).unwrap());

        Ok(InitFrame {
            id: id.try_into()?,
            uuid: uuid.into_bytes(),
            options,
            sig_pub_key: Box::new(client_ecdsa_key),
            keyneg_pub_key: client_ecdh_key.get_pub_key_to_bytes().into_boxed_slice(),
            keyneg_keys: None,
            keyneg_signature: client_signature.to_bytes(),
            nonce_pub_key: sec_ecdh_pub_key,
            nonce_keyneg_keys: None,
        })
    }
}

impl Frame for InitFrame {
    fn to_bytes(&self) -> Vec<u8> {
        let options_bytes: Vec<u8> = self.options.clone().into();
        let options_size: u32 = options_bytes.len() as u32;

        if let Some(nonce) = &self.nonce_keyneg_keys {
            [
                self.id.as_slice(),
                self.uuid.as_slice(),
                &options_size.to_be_bytes(),
                &options_bytes,
                &self.sig_pub_key.to_bytes(),
                &self.keyneg_pub_key,
                &nonce.to_bytes(),
                &self.keyneg_signature,
            ]
            .concat()
        } else {
            [
                self.id.as_slice(),
                self.uuid.as_slice(),
                &options_size.to_be_bytes(),
                &options_bytes,
                &self.sig_pub_key.to_bytes(),
                &self.keyneg_pub_key,
                &self.keyneg_signature,
            ]
            .concat()
        }
    }

    /// Create new InitFrame from any type that implements `AsRef<[u8]>`
    fn from_bytes<T>(bytes: T) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: AsRef<[u8]>,
    {
        let boxed_bytes = bytes.as_ref();
        InitFrame::try_from(boxed_bytes)
    }
}

impl Default for InitFrame {
    /// Generates a InitFrame ready to be sent to another client.
    fn default() -> InitFrame {
        let appstate_r = APPSTATE
            .get()
            .unwrap()
            .read()
            .expect("could not get read handle on appstate");
        let id = appstate_r.user_id;
        let uuid = appstate_r.uuid.into_bytes();

        let options = Options {
            frame_type: FrameType::Init,
            init_opts: Some(
                InitOptions::new_with_enc_type(EncryptionType::Legacy)
                    .status(0)
                    .nonce_secondary_key(true),
            ),
            ..Default::default()
        };
        let ecdsa_pub_key = Box::new(appstate_r.server_keys.ecdsa.get_pub_key().clone());
        let ecdh_keys = Box::new(ECDHKeys::init());
        let ecdh_pub_key = ecdh_keys.get_pub_key_to_bytes().into_boxed_slice();

        let nonce_keyneg_keys = Box::new(ECDHKeys::init());
        let nonce_pub_key = Some(nonce_keyneg_keys.get_pub_key_to_bytes().into_boxed_slice());

        let ecdh_signature = appstate_r
            .server_keys
            .ecdsa
            .sign(&ecdh_keys.get_pub_key_to_bytes());

        InitFrame {
            id,
            uuid,
            options,
            sig_pub_key: ecdsa_pub_key,
            keyneg_pub_key: ecdh_pub_key,
            keyneg_keys: Some(ecdh_keys as Box<dyn KeyNeg>),
            keyneg_signature: ecdh_signature.to_bytes(),
            nonce_pub_key,
            nonce_keyneg_keys: Some(nonce_keyneg_keys as Box<dyn KeyNeg>),
        }
    }
}

fn init_frame_kyberdith_handler(
    bytes: &[u8],
    _opts: &Options,
    id: &[u8],
    uuid: Uuid,
    self_frame: InitFrame,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let dith_pubkey = DilithiumPubKey::from_bytes(&bytes[..KYBER_PUBKEY_INDEX])?;
    let kyber_pubkey = &bytes[KYBER_PUBKEY_INDEX..KYBER_PUBKEY_INDEX2];
    let kyber_pubkey2 = &bytes[KYBER_PUBKEY_INDEX2..DITH_SIG_INDEX];
    let dith_sig = &bytes[DITH_SIG_INDEX..DITH_SIG_INDEX + pqc_dilithium::SIGNBYTES];

    dith_pubkey
        .verify(kyber_pubkey, dith_sig)
        .unwrap_or_else(|_| panic!("verify failed!"));

    if bytes.len()
        != DITH_SIG_INDEX + pqc_dilithium::SIGNBYTES + (pqc_kyber::KYBER_CIPHERTEXTBYTES * 2)
    {
        let mut trait_kyber_cipher = self_frame.keyneg_keys.unwrap();

        let kyber_cipher: &mut KyberDithCipher = trait_kyber_cipher.downcast_mut().unwrap();

        let ciphertext = kyber_cipher.gen_ciphertext(kyber_pubkey);

        let mut trait_nonce_kyber_cipher = self_frame.nonce_keyneg_keys.unwrap();
        let nonce_kyber_cipher: &mut KyberDithCipher =
            trait_nonce_kyber_cipher.downcast_mut().unwrap();

        let nonce_ciphertext = nonce_kyber_cipher.gen_ciphertext(kyber_pubkey2);

        let client_keypair = ClientKeypair::new()
            .pub_key(Box::new(dith_pubkey))
            .shared_secret(
                kyber_cipher
                    .shared_secret
                    .unwrap()
                    .to_vec()
                    .into_boxed_slice(),
            )
            .nonce_key(Some(
                nonce_kyber_cipher
                    .shared_secret
                    .unwrap()
                    .as_ref()
                    .try_into()?,
            ))
            .uuid(uuid)
            .id(String::from_utf8(id.to_vec()).unwrap());

        APPSTATE
            .get()
            .unwrap()
            .write()?
            .client_keys
            .insert(client_keypair.uuid, client_keypair);

        log::trace!("added uuid to clientkeypair: {}", &uuid);

        let options_bytes: Vec<u8> = self_frame.options.into();
        let options_size: u32 = options_bytes.len() as u32;

        Ok([
            self_frame.id.as_slice(),
            self_frame.uuid.as_slice(),
            &options_size.to_be_bytes(),
            &options_bytes,
            &self_frame.sig_pub_key.to_bytes(),
            &self_frame.keyneg_pub_key,
            &self_frame.nonce_pub_key.unwrap(),
            &self_frame.keyneg_signature,
            &ciphertext,
            &nonce_ciphertext,
        ]
        .concat())
    } else {
        let ciphertext = &bytes[CIPHERTEXT_INDEX..NONCE_CIPHERTEXT_INDEX];
        let nonce_ciphertext = &bytes[NONCE_CIPHERTEXT_INDEX..];

        let shared_secret: Box<KyberDithCipher> = self_frame
            .keyneg_keys
            .unwrap()
            .downcast()
            .unwrap_or_else(|_| panic!("could not downcast Box<dyn KeyNeg> to KyberDithCipher"));
        let nonce_shared_secret: Box<KyberDithCipher> = self_frame
            .nonce_keyneg_keys
            .unwrap()
            .downcast()
            .unwrap_or_else(|_| panic!("could not downcast Box<dyn KeyNeg> to KyberDithCipher"));

        let client_keypair = ClientKeypair::new()
            .pub_key(Box::new(dith_pubkey))
            .shared_secret(shared_secret.gen_shared_secret(ciphertext))
            .nonce_key(Some(
                nonce_shared_secret
                    .gen_shared_secret(nonce_ciphertext)
                    .as_ref()
                    .try_into()?,
            ))
            .uuid(uuid)
            .id(String::from_utf8(id.to_vec()).unwrap());

        APPSTATE
            .get()
            .unwrap()
            .write()?
            .client_keys
            .insert(client_keypair.uuid, client_keypair);

        log::trace!("added uuid to clientkeypair: {}", &uuid);

        Ok(vec![])
    }
}

fn init_frame_legacy_handler(
    bytes: &[u8],
    options: &Options,
    id: &[u8],
    uuid: Uuid,
    self_frame: InitFrame,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client_pub_key = ECDSAPubKey::from_sec1_bytes(&bytes[..97])?;
    let client_ecdh_key_bytes = &bytes[97..194];

    // If client sends an additional ECDH key (for the nonce)
    let is_second_ecdh_key = options
        .get_init_opts()
        .unwrap()
        .get_nonce_secondary_key()
        .unwrap();

    let (_sec_shared_secret, client_signature, is_nonce) = if is_second_ecdh_key {
        // Client has confirmed they sent another ECDH key.

        let sec_key_bytes = &bytes[194..291];
        // let sec_key = ECDHPubKey::from_sec1_bytes(sec_key_bytes).unwrap();
        let sec_ecdh_keys = self_frame.nonce_keyneg_keys.unwrap();
        let sec_shared_secret: Box<ECDHKeys> = sec_ecdh_keys
            .downcast()
            .unwrap_or_else(|_| panic!("could not downcast Box<dyn KeyNeg> to Box<ECDHKeys>"));
        (
            Some(sec_shared_secret.gen_shared_secret(sec_key_bytes)),
            Signature::from_der(&bytes[291..]).unwrap(),
            true,
        )
    } else {
        (None, Signature::from_der(&bytes[194..]).unwrap(), false)
    };

    //log::trace!("server res: key: {:#?}", client_signature);
    client_pub_key
        .verify(client_ecdh_key_bytes, &client_signature)
        .expect("signature verification failed :(");

    let ecdh_keys: Box<ECDHKeys> = self_frame
        .keyneg_keys
        .unwrap()
        .downcast()
        .unwrap_or_else(|_| panic!("could not downcast Box<dyn KeyNeg> to Box<ECDHKeys>"));

    let peer_shared_secret = ecdh_keys.gen_shared_secret(client_ecdh_key_bytes);
    log::trace!("client: secret: {:#?}", &peer_shared_secret);

    let client_keypair = ClientKeypair::new()
        .id(std::str::from_utf8(id)
            .expect("could not parse id")
            .to_string())
        .uuid(uuid)
        .pub_key(Box::new(client_pub_key))
        .shared_secret(peer_shared_secret);

    log::trace!("added uuid to clientkeypair: {}", &uuid);

    APPSTATE
        .get()
        .unwrap()
        .write()?
        .client_keys
        .insert(client_keypair.uuid, client_keypair);

    let options_bytes: Vec<u8> = self_frame.options.into();
    let options_size: u32 = options_bytes.len() as u32;

    if is_nonce {
        Ok([
            self_frame.id.as_slice(),
            self_frame.uuid.as_slice(),
            &options_size.to_be_bytes(),
            &options_bytes,
            &self_frame.sig_pub_key.to_bytes(),
            &self_frame.keyneg_pub_key,
            &self_frame.nonce_pub_key.unwrap(),
            &self_frame.keyneg_signature,
        ]
        .concat())
    } else {
        Ok([
            self_frame.id.as_slice(),
            self_frame.uuid.as_slice(),
            &options_size.to_be_bytes(),
            &options_bytes,
            &self_frame.sig_pub_key.to_bytes(),
            &self_frame.keyneg_pub_key,
            &self_frame.keyneg_signature,
        ]
        .concat())
    }
}

#[cfg(feature = "_clone")]
impl Clone for InitFrame {
    fn clone(&self) -> Self {
        let id = self.id;
        let uuid = self.uuid;
        let options = self.options.clone();
        let sig_pub_key = self.sig_pub_key.clone();
        let keyneg_pub_key = self.keyneg_pub_key.clone();
        let keyneg_keys = self.keyneg_keys.clone();
        let keyneg_signature = self.keyneg_signature.clone();
        let nonce_pub_key = self.nonce_pub_key.clone();
        let nonce_keyneg_keys = self.nonce_keyneg_keys.clone();

        Self {
            id,
            uuid,
            options,
            sig_pub_key,
            keyneg_pub_key,
            keyneg_keys,
            keyneg_signature,
            nonce_pub_key,
            nonce_keyneg_keys,
        }
    }
}

impl InitFrame {
    /// Used when you have received an InitFrame from another peer. Moves out of the current
    /// InitFrame object, so `from_peer` converts `self` into bytes that are ready to be sent to
    /// the peer.
    /// ```ignore
    /// let new_init_frame = InitFrame::default();
    /// let received_init_frame: Vec<u8> = received_bytes;
    /// let init_frame_bytes_to_be_sent = new_init_frame.from_peer(&received_init_frame).unwrap();
    /// ```
    pub fn from_peer<T>(self, bytes: T) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        T: AsRef<[u8]>,
    {
        let frame_bytes = bytes.as_ref();
        let id = &frame_bytes[0..=2];
        let uuid = Uuid::from_slice(&frame_bytes[3..=18]).unwrap();
        let options_len = u32::from_be_bytes(frame_bytes[19..=22].try_into()?);

        let body = &frame_bytes[23..];

        // PERF: Must wait until "slice_first_last_chunk" feature is stablized
        // in order to use arrays instead
        let options_bytes = &body[..options_len as usize];

        let options = Options::try_from(options_bytes)?;

        let enc_type = options
            .get_init_opts()
            .ok_or("somehow no init opts?")?
            .get_encryption_type()
            .ok_or("somehow no enc_type?")?;

        let init_vars_slice = &body[options_len as usize..];

        match enc_type {
            EncryptionType::KyberDith => {
                init_frame_kyberdith_handler(init_vars_slice, &options, id, uuid, self)
            }
            EncryptionType::Legacy => {
                init_frame_legacy_handler(init_vars_slice, &options, id, uuid, self)
            }
            _ => Err("invalid encryption time".into()),
        }
    }

    pub fn new(enc_type: EncryptionType) -> InitFrame {
        let appstate_r = APPSTATE
            .get()
            .unwrap()
            .read()
            .expect("could not get read handle on appstate");
        let id = appstate_r.user_id;
        let uuid = appstate_r.uuid.into_bytes();

        let options = Options {
            frame_type: FrameType::Init,
            init_opts: Some(
                InitOptions::new_with_enc_type(enc_type)
                    .status(0)
                    .nonce_secondary_key(true),
            ),
            ..Default::default()
        };

        match enc_type {
            EncryptionType::Legacy => {
                let ecdsa_pub_key = Box::new(appstate_r.server_keys.ecdsa.get_pub_key());
                let ecdh_keys = Box::new(ECDHKeys::init());
                let ecdh_pub_key = ecdh_keys.get_pub_key_to_bytes().into_boxed_slice();

                let nonce_keyneg_keys = Box::new(ECDHKeys::init());
                let nonce_pub_key =
                    Some(nonce_keyneg_keys.get_pub_key_to_bytes().into_boxed_slice());

                let ecdh_signature = appstate_r
                    .server_keys
                    .ecdsa
                    .sign(&ecdh_keys.get_pub_key_to_bytes());

                InitFrame {
                    id,
                    uuid,
                    options,
                    sig_pub_key: ecdsa_pub_key,
                    keyneg_pub_key: ecdh_pub_key,
                    keyneg_keys: Some(ecdh_keys as Box<dyn KeyNeg>),
                    keyneg_signature: ecdh_signature.to_bytes(),
                    nonce_keyneg_keys: Some(nonce_keyneg_keys as Box<dyn KeyNeg>),
                    nonce_pub_key,
                }
            }
            EncryptionType::KyberDith => {
                let sig_pub_key = appstate_r.server_keys.dilithium.get_pub();
                let keyneg_keys = KyberDithCipher::init();
                let keyneg_pub_key = keyneg_keys.to_bytes();
                let keyneg_signature = appstate_r.server_keys.dilithium.sign(&keyneg_pub_key);
                let nonce_keyneg_keys = KyberDithCipher::init();
                let nonce_pub_key = nonce_keyneg_keys.to_bytes();

                InitFrame {
                    id,
                    uuid,
                    options,
                    sig_pub_key: Box::new(sig_pub_key),
                    keyneg_pub_key: keyneg_pub_key.into_boxed_slice(),
                    keyneg_keys: Some(Box::new(keyneg_keys)),
                    keyneg_signature,
                    nonce_keyneg_keys: Some(Box::new(nonce_keyneg_keys)),
                    nonce_pub_key: Some(nonce_pub_key.into_boxed_slice()),
                }
            }
            _ => todo!(),
        }
    }

    pub fn set_options(&mut self, opts: Options) {
        self.options = opts;
    }
}

/// `DataFrame`s can only be sent to clients that you have paired with via `InitFrame`.
/// `DataFrame`s contain metadata (options, uuid) just like `InitFrame`s, however the body
/// (excluding the options) are encrypted.
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
        let options_bytes: Vec<u8> = self.options.clone().into();
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
    fn from_bytes<T>(bytes: T) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: AsRef<[u8]>,
    {
        let boxed_bytes = bytes.as_ref();
        DataFrame::try_from(boxed_bytes)
    }
}

impl DataFrame {
    pub fn new<'a, T: Into<&'a [u8]>>(input: T) -> Self {
        let id = Some(APPSTATE.get().unwrap().try_read().unwrap().user_id);
        let uuid = Some(
            APPSTATE
                .get()
                .unwrap()
                .try_read()
                .unwrap()
                .uuid
                .into_bytes(),
        );
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
        let app_state = APPSTATE.get().unwrap().read()?;
        let target_keychain = app_state
            .client_keys
            .get(&target_uuid)
            .ok_or("could not find client keys")?;

        let mut hasher = Blake2b192::new();

        if let Some(nonce) = &target_keychain.nonce_key {
            log::trace!("encoding with secondary ecdh key");
            hasher.update(nonce);
        } else {
            let shared_secret_bytes = if let Some(kyber) = target_keychain.kyber {
                kyber.to_vec()
            } else {
                target_keychain
                    .shared_secret
                    .as_ref()
                    .ok_or("couldn't find ecdh keys")
                    .unwrap()
                    .to_vec()
            };
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
        self.uuid = Some(*app_state.uuid.as_bytes());
        self.body = encrypted_body.into_boxed_slice();

        Ok(())
    }

    pub fn encode_frame_with_addr(
        &mut self,
        target_peer: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app_state = APPSTATE.get().unwrap().read()?;
        log::debug!("keychain: {:#?}", app_state.client_keys);
        let target_keychain = app_state
            .client_keys
            .iter()
            .filter(|(_, i)| i.ip.is_some())
            .find(|(_, i)| i.ip.unwrap() == target_peer)
            .map(|(_, i)| i)
            .ok_or("could not find client keys")?;

        let shared_secret_bytes = if let Some(kyber) = target_keychain.kyber {
            kyber.to_vec()
        } else {
            target_keychain
                .shared_secret
                .as_ref()
                .ok_or("couldn't find ecdh keys")
                .unwrap()
                .to_vec()
        };

        let mut hasher = Blake2b192::new();
        let res = if let Some(nonce) = &target_keychain.nonce_key {
            log::trace!("decrypting frame with secondary ecdh key");
            hasher.update(nonce);
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
        let target_uuid = Uuid::from_bytes(self.uuid.ok_or("self.uuid is invalid")?);
        log::trace!("target_uuid: {target_uuid}");

        let app_state = APPSTATE.get().unwrap().read()?;
        let target_keychain = app_state
            .client_keys
            .get(&target_uuid)
            .ok_or("could not find client keys")?;

        let shared_secret_bytes = if let Some(kyber) = target_keychain.kyber {
            kyber.to_vec()
        } else {
            target_keychain
                .shared_secret
                .as_ref()
                .ok_or("couldn't find ecdh keys")
                .unwrap()
                .to_vec()
        };

        let mut hasher = Blake2b192::new();
        let res = if let Some(nonce) = &target_keychain.nonce_key {
            log::trace!("decrypting frame with secondary ecdh key");
            hasher.update(nonce);
            hasher.finalize()
        } else {
            hasher.update(shared_secret_bytes);
            hasher.finalize()
        };

        let decrypted_body = target_keychain
            .chacha
            .as_ref()
            .ok_or("failed to decrypt body")?
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
    #[allow(dead_code)]
    pub(crate) fn encrypt_frame_with_keypair(
        &mut self,
        keypair: &ClientKeypair,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let shared_secret_bytes = keypair.shared_secret.as_ref().ok_or("failed to get ecdh")?;

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
        let shared_secret_bytes = keypair.shared_secret.as_ref().ok_or("failed to get ecdh")?;

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

impl TryFrom<&[u8]> for DataFrame {
    type Error = Box<dyn std::error::Error>;
    fn try_from(frame_slice: &[u8]) -> Result<DataFrame, Box<dyn std::error::Error>> {
        log::trace!("size of frame: {}", frame_slice.len());
        let id = frame_slice[0..=2].try_into()?;
        let uuid = frame_slice[3..=18].try_into()?;
        let options_len = usize::try_from(u32::from_be_bytes(frame_slice[19..=22].try_into()?))?;
        let options = Options::try_from(&frame_slice[23..23 + options_len])?;
        let body = frame_slice[23 + options_len..].into();

        if std::str::from_utf8(&frame_slice[0..=2]).is_err() {
            return Err("id is not a valid string".into());
        };

        let id = Some(id);
        let uuid = Some(uuid);

        log::trace!("data frame succesfully parsed");

        Ok(DataFrame {
            id,
            uuid,
            body,
            options,
        })
    }
}
