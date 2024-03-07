use crate::crypto::{
    aes::ChaChaCipher,
    dilithium::DilithiumKeyPair,
    key_exchange::{ECDHKeys, ECDSAKeys},
    PubKey,
};

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{OnceLock, RwLock},
};
use uuid::Uuid;

pub struct AppState {
    pub server_keys: ServerKeys,
    pub client_keys: HashMap<Uuid, ClientKeypair>,
    pub is_http_server_on: bool,
    pub server_addr: Option<SocketAddr>,
    pub user_id: [u8; 3],
    pub uuid: Uuid,
}

impl AppState {
    pub fn init() -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(()) = APPSTATE.set(RwLock::new(AppState::init_keys())) {
            Ok(())
        } else {
            Err("failed to init, likely because AppState has been previously initialized".into())
        }
    }

    pub(crate) fn init_keys() -> AppState {
        let server_keys = ServerKeys::init();
        let client_keys = HashMap::new();
        AppState {
            server_keys,
            client_keys,
            server_addr: None,
            is_http_server_on: false,
            uuid: Uuid::new_v4(),
            user_id: [0u8; 3],
        }
    }

    pub fn init_with_priv_key(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let server_keys = ServerKeys::init_with_priv_key(bytes)?;
        let client_keys = HashMap::new();
        if let Ok(()) = APPSTATE.set(RwLock::new(AppState {
            server_keys,
            client_keys,
            server_addr: None,
            is_http_server_on: false,
            uuid: Uuid::new_v4(),
            user_id: [0u8; 3],
        })) {
            Ok(())
        } else {
            Err("failed to initialize with private key".into())
        }
    }

    pub fn priv_key_to_bytes(&self) -> Vec<u8> {
        [
            self.server_keys.ecdsa.to_bytes().unwrap(),
            self.server_keys.dilithium.to_bytes(),
        ]
        .concat()
    }
}

pub struct ClientKeypair {
    pub id: Option<String>,
    pub pub_key: Option<Box<dyn PubKey>>,
    pub shared_secret: Option<Box<[u8]>>,
    pub kyber: Option<[u8; 32]>,
    pub chacha: Option<ChaChaCipher>,
    pub uuid: Uuid,
    pub ip: Option<SocketAddr>,
    pub nonce_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for ClientKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(id: {}\n, ecdsa: {:?}\n, ecdh: {:?}\n, uuid: {}\n)",
            self.id.as_ref().unwrap(),
            self.pub_key.as_ref().unwrap().to_bytes(),
            self.shared_secret.as_ref().unwrap().as_ref(),
            self.uuid
        )
    }
}

impl Default for ClientKeypair {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientKeypair {
    pub fn new() -> ClientKeypair {
        ClientKeypair {
            id: None,
            pub_key: None,
            shared_secret: None,
            kyber: None,
            chacha: None,
            uuid: Uuid::new_v4(),
            ip: None,
            nonce_key: None,
        }
    }

    pub fn from_bytes<T>(bytes: T) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: AsRef<[u8]>,
    {
        let byte_slice = bytes.as_ref();
        let uuid = Uuid::from_slice(&byte_slice[..16])?;
        let shared_secret: [u8; 32] = byte_slice[16..48].try_into()?;
        let nonce: [u8; 32] = byte_slice[48..].try_into()?;
        Ok(ClientKeypair::new()
            .uuid(uuid)
            .shared_secret(Box::new(shared_secret))
            .nonce_key(Some(nonce)))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = [
            self.uuid.as_bytes(),
            self.shared_secret.as_ref().unwrap().as_ref(),
            self.nonce_key.as_ref().unwrap().as_ref(),
        ]
        .concat();

        log::debug!("client_keypair byte len: {}", bytes.len());
        bytes
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn pub_key(mut self, pub_key: Box<dyn PubKey>) -> Self {
        self.pub_key = Some(pub_key);
        self
    }

    pub fn kyber(mut self, shared_secret: [u8; 32]) -> Self {
        self.chacha = Some(ChaChaCipher::init_with_raw_bytes(&shared_secret));
        self.kyber = Some(shared_secret);
        self
    }

    pub fn shared_secret(mut self, shared_secret: Box<[u8]>) -> Self {
        self.chacha = Some(ChaChaCipher::init_with_raw_bytes(&shared_secret));
        self.shared_secret = Some(shared_secret);
        self
    }

    pub fn ip(mut self, ip: Option<SocketAddr>) -> Self {
        self.ip = ip;
        self
    }

    pub fn uuid(mut self, uuid: Uuid) -> Self {
        self.uuid = uuid;
        self
    }

    pub fn nonce_key(mut self, key: Option<[u8; 32]>) -> Self {
        self.nonce_key = key;
        self
    }
}

pub struct ServerKeys {
    pub ecdsa: ECDSAKeys,
    pub ecdh: ECDHKeys,
    pub dilithium: DilithiumKeyPair,
}

impl ServerKeys {
    pub fn init() -> ServerKeys {
        let ecdsa = ECDSAKeys::init();
        let ecdh = ECDHKeys::init();
        let dilithium = DilithiumKeyPair::init();
        ServerKeys {
            ecdsa,
            ecdh,
            dilithium,
        }
    }

    pub(crate) fn init_with_priv_key(
        bytes: &[u8],
    ) -> Result<ServerKeys, Box<dyn std::error::Error>> {
        let ecdsa = ECDSAKeys::from_raw_bytes(&bytes[0..185])?;
        let ecdh = ECDHKeys::init();
        let dilithium = DilithiumKeyPair::init_from_bytes(&bytes[185..]);

        if let Ok(dilithium) = dilithium {
            Ok(ServerKeys {
                ecdsa,
                ecdh,
                dilithium,
            })
        } else {
            Err("invalid dilithium keys".into())
        }
    }
}

pub static APPSTATE: OnceLock<RwLock<AppState>> = OnceLock::new();
