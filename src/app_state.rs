use crate::crypto::key_exchange::{ECDHKeys, ECDSAKeys};
use once_cell::sync::Lazy;
use p384::{
    ecdh::{EphemeralSecret, SharedSecret},
    ecdsa::VerifyingKey, PublicKey,
};
use std::sync::RwLock;

pub struct AppState {
    pub server_keys: ServerKeys,
    pub client_keys: Vec<ClientKeypair>,
    pub is_http_server_on: bool,
}

unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

impl AppState {
    pub fn init() -> AppState {
        let server_keys = ServerKeys::init();
        let client_keys = vec![];
        AppState {
            server_keys,
            client_keys,
            is_http_server_on: false
        }
    }
}

pub struct ClientKeypair {
    pub id: Option<String>,
    pub ecdsa: Option<VerifyingKey>,
    pub ecdh: Option<SharedSecret>,
}

impl ClientKeypair {
    pub fn new() -> ClientKeypair {
        return ClientKeypair {
            id: None,
            ecdsa: None,
            ecdh: None
        }
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn ecdsa(mut self, pub_key: VerifyingKey) -> Self {
        self.ecdsa = Some(pub_key);
        self
    }

    pub fn ecdh(mut self, shared_secret: SharedSecret) -> Self {
        self.ecdh = Some(shared_secret);
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
        return ServerKeys { ecdsa, ecdh };
    }
}

pub static APPSTATE: Lazy<RwLock<AppState>> = Lazy::new(|| RwLock::new(AppState::init()));
