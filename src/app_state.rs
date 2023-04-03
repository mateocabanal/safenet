use crate::crypto::{key_exchange::{ECDHKeys, ECDSAKeys}, aes::ChaChaCipher};
use once_cell::sync::Lazy;
use p384::{
    ecdh::SharedSecret,
    ecdsa::VerifyingKey,
};
use std::{sync::RwLock, net::SocketAddr};
use uuid::Uuid;

pub struct AppState {
    pub server_keys: ServerKeys,
    pub client_keys: Vec<ClientKeypair>,
    pub is_http_server_on: bool,
    pub server_addr: Option<SocketAddr>,
    pub user_id: [u8; 3],
    pub uuid: Uuid
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
            server_addr: None,
            is_http_server_on: false,
            uuid: Uuid::new_v4(),
            user_id: [0u8; 3]
        }
    }
}

pub struct ClientKeypair {
    pub id: Option<String>,
    pub ecdsa: Option<VerifyingKey>,
    pub ecdh: Option<SharedSecret>,
    pub chacha: Option<ChaChaCipher>,
    pub uuid: Uuid,
    pub ip: Option<SocketAddr>
}

impl std::fmt::Debug for ClientKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(id: {}\n, ecdsa: {:?}\n, ecdh: {:?}\n, ip: {:?}\n, uuid: {}\n)", self.id.as_ref().unwrap(), self.ecdsa.unwrap().to_encoded_point(true).to_bytes(), self.ecdh.as_ref().unwrap().raw_secret_bytes(), self.ip.expect("failed to get ip"), self.uuid)
    }
}

impl ClientKeypair {
    pub fn new() -> ClientKeypair {
        return ClientKeypair {
            id: None,
            ecdsa: None,
            ecdh: None,
            chacha: None,
            uuid: Uuid::new_v4(),
            ip: None
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
        self.chacha = Some(ChaChaCipher::init_with_key(&shared_secret));
        self.ecdh = Some(shared_secret);
        self
    }

    pub fn ip(mut self, ip: SocketAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    pub fn uuid(mut self, uuid: Uuid) -> Self {
        self.uuid = uuid;
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
