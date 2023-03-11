use crate::crypto::key_exchange::ECDSAKeys;
use once_cell::sync::Lazy;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub struct AppState {
    pub ecdsa_server_keys: ECDSAKeys,
    pub is_http_server_on: bool,
}

unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

impl AppState {
    pub fn init() -> AppState {
        let ecdsa_server_keys = ECDSAKeys::init();
        AppState {
            ecdsa_server_keys,
            is_http_server_on: false,
        }
    }
}

pub static APPSTATE: Lazy<RwLock<AppState>> = Lazy::new(|| RwLock::new(AppState::init()));
