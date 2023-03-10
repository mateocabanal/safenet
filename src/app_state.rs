use crate::crypto::key_exchange::ECDSAKeys;
use once_cell::sync::Lazy;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub struct AppState {
    pub ecdsa_server_keys: ECDSAKeys,
    pub http_client: hyper::Client,
}

impl AppState {
    pub fn init() -> AppState {
        let ecdsa_server_keys = ECDSAKeys::init();
        let http_client = hyper::Client::new();
        AppState { ecdsa_server_keys, http_client }
    }
}

pub static APPSTATE: Lazy<RwLock<AppState>> = Lazy::new(|| RwLock::new(AppState::init()));
