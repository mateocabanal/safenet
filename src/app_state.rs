use crate::crypto::{
    aes::ChaChaCipher,
    key_exchange::{ECDHKeys, ECDSAKeys, ECDSAPubKey, SharedSecret},
    kyber::KyberCipher,
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
        self.server_keys.ecdsa.to_bytes().unwrap()
    }
}

pub struct ClientKeypair {
    pub id: Option<String>,
    pub ecdsa: Option<ECDSAPubKey>,
    pub ecdh: Option<SharedSecret>,
    pub kyber: Option<[u8; 32]>,
    pub chacha: Option<ChaChaCipher>,
    pub uuid: Uuid,
    pub ip: Option<SocketAddr>,
    pub nonce_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for ClientKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(id: {}\n, ecdsa: {:?}\n, ecdh: {:?}\n, uuid: {}\n)",
            self.id.as_ref().unwrap(),
            self.ecdsa.as_ref().unwrap().to_bytes(),
            self.ecdh.as_ref().unwrap().raw_secret_bytes(),
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
            ecdsa: None,
            ecdh: None,
            kyber: None,
            chacha: None,
            uuid: Uuid::new_v4(),
            ip: None,
            nonce_key: None,
        }
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn ecdsa(mut self, pub_key: ECDSAPubKey) -> Self {
        self.ecdsa = Some(pub_key);
        self
    }

    pub fn kyber(mut self, shared_secret: [u8; 32]) -> Self {
        self.chacha = Some(ChaChaCipher::init_with_raw_bytes(&shared_secret));
        self.kyber = Some(shared_secret);
        self
    }

    pub fn ecdh(mut self, shared_secret: SharedSecret) -> Self {
        self.chacha = Some(ChaChaCipher::init_with_key(&shared_secret));
        self.ecdh = Some(shared_secret);
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

    pub fn nonce_key(mut self, key: Option<Vec<u8>>) -> Self {
        self.nonce_key = key;
        self
    }
}

pub struct ServerKeys {
    pub ecdsa: ECDSAKeys,
    pub ecdh: ECDHKeys,
}

impl ServerKeys {
    pub fn init() -> ServerKeys {
        let ecdsa = ECDSAKeys::init();
        let ecdh = ECDHKeys::init();
        ServerKeys { ecdsa, ecdh }
    }

    fn init_with_priv_key(bytes: &[u8]) -> Result<ServerKeys, Box<dyn std::error::Error>> {
        let ecdsa = ECDSAKeys::from_raw_bytes(bytes)?;
        let ecdh = ECDHKeys::init();

        Ok(ServerKeys { ecdsa, ecdh })
    }
}

pub static APPSTATE: OnceLock<RwLock<AppState>> = OnceLock::new();
